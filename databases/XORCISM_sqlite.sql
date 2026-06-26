BEGIN TRANSACTION;

/****** 
Copyright (C) 2012-2015 Jerome Athias
XORCISM database
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
******/

;
/****** Object:  Table "ACCESSEDDIRECTORYLIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCESSEDDIRECTORYLIST"(
	"AccessedDirectoryListID" INTEGER NOT NULL,
	"AccessedDirectoryListGUID" TEXT NULL,
	"AccessedDirectoryListName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL
)

;
/****** Object:  Table "ACCESSEDFILELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCESSEDFILELIST"(
	"AccessedFileListID" INTEGER NOT NULL,
	"AccessedFileListGUID" TEXT NULL,
	"AccessedFileListName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL
)

;
/****** Object:  Table "ACCESSEDFILELISTFILES"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCESSEDFILELISTFILES"(
	"AccessedFileListFileID" INTEGER NOT NULL,
	"AccessedFileListFileGUID" TEXT NULL,
	"AccessedFileListID" INTEGER NOT NULL,
	"AccessedFileListGUID" TEXT NULL,
	"FileID" INTEGER NOT NULL,
	"FileGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ACCESSRECORD"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCESSRECORD"(
	"AccessRecordID" INTEGER NOT NULL,
	"AccessRecordGUID" TEXT NULL,
	"RecordGUID" TEXT NULL,
	"UserID" INTEGER NULL,
	"UserGUID" TEXT NULL,
	"AccessType" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL
)

;
/****** Object:  Table "ACCESSRECORDEVIDENCE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCESSRECORDEVIDENCE"(
	"AccessRecordEvidenceID" INTEGER NOT NULL,
	"AccessRecordID" INTEGER NULL,
	"AccessRecordGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACCESSRECORDHASH"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCESSRECORDHASH"(
	"AccessRecordHashID" INTEGER NOT NULL,
	"AccessRecordHashGUID" TEXT NULL,
	"AccessRecordID" INTEGER NOT NULL,
	"HashValue" TEXT NOT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL
)

;
/****** Object:  Table "ACCOUNT"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCOUNT"(
	"AccountID" INTEGER NOT NULL,
	"AccountGUID" TEXT NULL,
	"AccountName" TEXT NULL,
	"AccountDomain" TEXT NULL,
	"DomainNameID" INTEGER NULL,
	"DomainNameGUID" TEXT NULL,
	"AccountDescription" TEXT NULL,
	"Creation_Date" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"Modified_Date" TEXT NULL,
	BLOB TEXT NULL,
	"Last_Accessed_Time" TEXT NULL,
	"disabled" INTEGER NULL,
	"locked_out" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"OrganisationID" INTEGER NULL,
	"OrganisationGUID" TEXT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "ACCOUNTAUTHENTICATION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCOUNTAUTHENTICATION"(
	"AccountAuthenticationID" INTEGER NOT NULL,
	"AccountAuthenticationGUID" TEXT NULL,
	"AccountID" INTEGER NOT NULL,
	"AccountGUID" TEXT NULL,
	"AuthenticationTypeID" INTEGER NOT NULL,
	"AuthenticationTypeGUID" TEXT NULL,
	"Authentication_Data" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"Authentication_Token_Protection_Mechanism" TEXT NULL,
	"AuthenticationTokenProtectionMechanismID" INTEGER NULL,
	"AuthenticationTokenProtectionMechanismGUID" TEXT NULL,
	"StructuredAuthenticationMechanismID" INTEGER NULL,
	"StructuredAuthenticationMechanismGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ACCOUNTAUTHENTICATIONTYPE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCOUNTAUTHENTICATIONTYPE"(
	"AccountAuthenticationTypeID" INTEGER NOT NULL,
	"AccountAuthenticationTypeGUID" TEXT NULL,
	"AccountID" INTEGER NOT NULL,
	"AccountGUID" TEXT NULL,
	"AuthenticationTypeID" INTEGER NOT NULL,
	"AuthenticationTypeGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACCOUNTBLACKLIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCOUNTBLACKLIST"(
	"AccountBlacklistID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACCOUNTCHANGERECORD"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCOUNTCHANGERECORD"(
	"AccountChangeRecordID" INTEGER NOT NULL,
	"AccountChangeRecordGUID" TEXT NULL,
	"AccountID" INTEGER NOT NULL,
	"AccountGUID" TEXT NULL,
	"ChangeRecordID" INTEGER NOT NULL,
	"ChangeRecordGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACCOUNTDESCRIPTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCOUNTDESCRIPTION"(
	"AccountDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "ACCOUNTWHITELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACCOUNTWHITELIST"(
	"AccountWhitelistID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACE"(
	"ACEID" INTEGER NOT NULL,
	"ACEGUID" TEXT NULL
)

;
/****** Object:  Table "ACL"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACL"(
	"ACLID" INTEGER NOT NULL,
	"ACLGUID" TEXT NULL
)

;
/****** Object:  Table "ACLENTRY"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACLENTRY"(
	"ACLEntryID" INTEGER NOT NULL,
	"ACLEntryGUID" TEXT NULL,
	"ACLID" INTEGER NULL,
	"ACLGUID" TEXT NULL,
	"ACEID" INTEGER NULL,
	"ACEGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CreationObjectGUID" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACRONYM"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACRONYM"(
	"AcronymID" INTEGER NOT NULL,
	"AcronymGUID" TEXT NULL,
	"AcronymAbbreviation" TEXT NOT NULL,
	"AcronymPhrase" TEXT NOT NULL,
	"AcronymDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTION"(
	"ActionID" INTEGER NOT NULL,
	"ActionGUID" TEXT NULL,
	"ActionREFID" TEXT NULL,
	"ActionStatusID" INTEGER NULL,
	"ActionStatusName" TEXT NULL,
	"ordinal_position" INTEGER NULL,
	"ActionContextID" INTEGER NULL,
	"ActionContextName" TEXT NULL,
	"ActionTimestamp" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ActionDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"isSuspicious" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ACTIONACTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONACTION"(
	"ActionRelationshipID" INTEGER NOT NULL,
	"ActionRefID" INTEGER NOT NULL,
	"ActionRefGUID" TEXT NULL,
	"ActionRelationshipTypeID" INTEGER NOT NULL,
	"ActionRelationshipTypeName" TEXT NOT NULL,
	"ActionSubjectID" INTEGER NOT NULL,
	"ActionSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ACTIONACTIONARGUMENTNAME"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONACTIONARGUMENTNAME"(
	"ActionActionArgumentNameID" INTEGER NOT NULL,
	"ActionID" INTEGER NOT NULL,
	"ActionGUID" TEXT NULL,
	"ActionArgumentNameID" INTEGER NOT NULL,
	"ActionArgumentNameGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACTIONACTIONNAME"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONACTIONNAME"(
	"ActionActionNameID" INTEGER NOT NULL,
	"ActionID" INTEGER NOT NULL,
	"ActionGUID" TEXT NULL,
	"ActionNameID" INTEGER NOT NULL,
	"ActionNameGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACTIONACTIONTYPE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONACTIONTYPE"(
	"ActionActionTypeID" INTEGER NOT NULL,
	"ActionID" INTEGER NOT NULL,
	"ActionGUID" TEXT NULL,
	"ActionTypeID" INTEGER NOT NULL,
	"ActionTypeGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACTIONALIAS"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONALIAS"(
	"ActionAliasID" INTEGER NOT NULL,
	"ActionID" INTEGER NOT NULL,
	"ActionGUID" TEXT NULL,
	"ActionAlias" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ACTIONARGUMENTNAME"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONARGUMENTNAME"(
	"ActionArgumentNameID" INTEGER NOT NULL,
	"ActionArgumentNameGUID" TEXT NULL,
	"ActionArgumentNameName" TEXT NOT NULL,
	"ActionArgumentNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ACTIONASSOCIATION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONASSOCIATION"(
	"ActionAssociationID" INTEGER NOT NULL,
	"ActionObjectAssociationType" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ACTIONCOLLECTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONCOLLECTION"(
	"ActionCollectionID" INTEGER NOT NULL
)

;
/****** Object:  Table "ACTIONCONTEXT"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONCONTEXT"(
	"ActionContextID" INTEGER NOT NULL,
	"ActionContextGUID" TEXT NULL,
	"ActionContextName" TEXT NOT NULL,
	"ActionContextDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACTIONDESCRIPTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONDESCRIPTION"(
	"ActionDescriptionID" INTEGER NOT NULL,
	"ActionID" INTEGER NOT NULL,
	"ActionGUID" TEXT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"DescriptionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ACTIONDISCOVERYMETHOD"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONDISCOVERYMETHOD"(
	"ActionDiscoveryMethodID" INTEGER NOT NULL,
	"ActionID" INTEGER NOT NULL,
	"ActionGUID" TEXT NULL,
	"DiscoveryMethodID" INTEGER NOT NULL,
	"DiscoveryMethodGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ACTIONIMPLEMENTATION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONIMPLEMENTATION"(
	"ActionImplementationID" INTEGER NOT NULL
)

;
/****** Object:  Table "ACTIONNAME"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONNAME"(
	"ActionNameID" INTEGER NOT NULL,
	"ActionNameName" TEXT NOT NULL,
	"ActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ACTIONOBJECTASSOCIATIONTYPE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONOBJECTASSOCIATIONTYPE"(
	"ActionObjectAssociationTypeID" INTEGER NOT NULL,
	"ActionObjectAssociationTypeName" TEXT NOT NULL,
	"ActionObjectAssociationTypeDescription" TEXT NULL,
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
/****** Object:  Table "ACTIONPLAN"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONPLAN"(
	"ActionPlanID" INTEGER NOT NULL
)

;
/****** Object:  Table "ACTIONPOOL"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONPOOL"(
	"ActionPoolID" INTEGER NOT NULL
)

;
/****** Object:  Table "ACTIONRELATIONSHIPTYPE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONRELATIONSHIPTYPE"(
	"ActionRelationshipTypeID" INTEGER NOT NULL,
	"ActionRelationshipTypeName" TEXT NOT NULL,
	"ActionRelationshipTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ACTIONSTATUS"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONSTATUS"(
	"ActionStatusID" INTEGER NOT NULL,
	"ActionStatusName" TEXT NOT NULL,
	"ActionStatusDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ACTIONTAKEN"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONTAKEN"(
	"ActionTakenID" INTEGER NOT NULL,
	"ActionTakenGUID" TEXT NULL,
	"ActionName" TEXT NOT NULL,
	"ActionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ACTIONTAKENFORINCIDENT"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONTAKENFORINCIDENT"(
	"ActionTakenForIncidentID" INTEGER NOT NULL,
	"ActionTakenID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreationObjectID" INTEGER NULL
)

;
/****** Object:  Table "ACTIONTAKENFORTHREATCAMPAIGN"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONTAKENFORTHREATCAMPAIGN"(
	"ActionTakenForThreatCampaignID" INTEGER NOT NULL,
	"ActionTakenID" INTEGER NOT NULL,
	"ThreatCampaignID" INTEGER NOT NULL,
	"ThreatActorID" INTEGER NULL,
	"ActionStartDate" TEXT NULL,
	"ActionEndDate" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreationObjectID" INTEGER NULL
)

;
/****** Object:  Table "ACTIONTYPE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIONTYPE"(
	"ActionTypeID" INTEGER NOT NULL,
	"ActionTypeGUID" TEXT NULL,
	"ActionTypeName" TEXT NOT NULL,
	"ActionTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ACTIVATIONFUNCTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIVATIONFUNCTION"(
	"ActivationFunctionID" INTEGER NOT NULL,
	"FunctionID" INTEGER NULL
)

;
/****** Object:  Table "ACTIVATIONZONE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIVATIONZONE"(
	"ActivationZoneID" INTEGER NOT NULL,
	"ActivationZoneGUID" TEXT NULL,
	"ActivationZoneText" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ACTIVATIONZONEFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ACTIVATIONZONEFORATTACKPATTERN"(
	"AttackPatternActivationZoneID" INTEGER NOT NULL,
	"AttackPatternActivationZoneGUID" TEXT NULL,
	"ActivationZoneID" INTEGER NOT NULL,
	"ActivationZoneGUID" TEXT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternGUID" TEXT NULL,
	"capec_id" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ADDRESS"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ADDRESS"(
	"AddressID" INTEGER NOT NULL,
	"AddressGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"AddressCategoryID" INTEGER NULL,
	"category" TEXT NULL,
	"Address_Value" TEXT NULL,
	"VLAN_Name" TEXT NULL,
	"VLAN_Num" INTEGER NULL,
	"is_source" INTEGER NULL,
	"is_destination" INTEGER NULL,
	"is_spoofed" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "ADDRESSBLACKLIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ADDRESSBLACKLIST"(
	"AddressBlacklistID" INTEGER NOT NULL,
	"AddressID" INTEGER NULL,
	"EmailID" INTEGER NULL,
	"emailaddress" TEXT NULL,
	"is_source" INTEGER NULL,
	"is_destination" INTEGER NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ADDRESSCATEGORY"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ADDRESSCATEGORY"(
	"AddressCategoryID" INTEGER NOT NULL,
	"AddressCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"AddressCategoryName" TEXT NULL,
	"AddressCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ADDRESSCOUNTRY"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ADDRESSCOUNTRY"(
	"AddressCountryID" INTEGER NOT NULL,
	"AddressID" INTEGER NULL,
	"AddressGUID" TEXT NULL,
	"CountryID" INTEGER NULL,
	"CountryGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ADDRESSREPUTATION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ADDRESSREPUTATION"(
	"AddressReputationID" INTEGER NOT NULL,
	"AddressID" INTEGER NULL,
	"AddressGUID" TEXT NULL,
	"ReputationID" INTEGER NULL,
	"ReputationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ADDRESSWHITELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ADDRESSWHITELIST"(
	"AddressWhitelistID" INTEGER NOT NULL,
	"AddressID" INTEGER NULL,
	"EmailID" INTEGER NULL,
	"emailaddress" TEXT NULL,
	"is_source" INTEGER NULL,
	"is_destination" INTEGER NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ADVISORY"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ADVISORY"(
	"AdvisoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "AFFECTEDRESOURCE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "AFFECTEDRESOURCE"(
	"AffectedResourceID" INTEGER NOT NULL,
	"AffectedResourceName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "AGENT"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "AGENT"(
	"AgentID" INTEGER NOT NULL,
	"AgentGUID" TEXT NULL,
	"ipaddressIPv4" TEXT NULL,
	"AgentStatus" TEXT NULL,
	"AgentLoadValue" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"SensorID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ALGEBRAIC"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ALGEBRAIC"(
	"AlgebraicID" INTEGER NOT NULL
)

;
/****** Object:  Table "ALGORITHM"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ALGORITHM"(
	"AlgorithmID" INTEGER NOT NULL,
	"AlgorithmName" TEXT NULL,
	"AlgorithmVersion" TEXT NULL,
	"AlgorithmVersionID" INTEGER NULL,
	"AlgorithmDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ALGORITHMDESCRIPTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ALGORITHMDESCRIPTION"(
	"AlgorithmDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "ALGORITHMREFERENCE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ALGORITHMREFERENCE"(
	"AlgorithmReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "ALGORITHMTAG"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ALGORITHMTAG"(
	"AlgorithmTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "ANTIBEHAVIORALANALYSISSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTIBEHAVIORALANALYSISSTRATEGICOBJECTIVE"(
	"AntiBehavioralAnalysisStrategicObjectiveID" INTEGER NOT NULL,
	"AntiBehavioralAnalysisStrategicObjectiveName" TEXT NULL,
	"AntiBehavioralAnalysisStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ANTIBEHAVIORALANALYSISTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTIBEHAVIORALANALYSISTACTICALOBJECTIVE"(
	"AntiBehavioralAnalysisTacticalObjectiveID" INTEGER NOT NULL,
	"AntiBehavioralAnalysisTacticalObjectiveName" TEXT NULL,
	"AntiBehavioralAnalysisTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ANTIBEHAVIORANALYSISPROPERTIES"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTIBEHAVIORANALYSISPROPERTIES"(
	"AntiBehavioralAnalysisPropertiesID" INTEGER NOT NULL,
	"AntiBehavioralAnalysisPropertiesName" TEXT NULL,
	"AntiBehavioralAnalysisPropertiesDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ANTICODEANALYSISSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTICODEANALYSISSTRATEGICOBJECTIVE"(
	"AntiCodeAnalysisStrategicObjectiveID" INTEGER NOT NULL,
	"AntiCodeAnalysisStrategicObjectiveName" TEXT NULL,
	"AntiCodeAnalysisStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ANTICODEANALYSISTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTICODEANALYSISTACTICALOBJECTIVE"(
	"AntiCodeAnalysisTacticalObjectiveID" INTEGER NOT NULL,
	"AntiCodeAnalysisTacticalObjectiveName" TEXT NULL,
	"AntiCodeAnalysisTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ANTIDETECTIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTIDETECTIONSTRATEGICOBJECTIVE"(
	"AntiDetectionStrategicObjectiveID" INTEGER NOT NULL,
	"AntiDetectionStrategicObjectiveName" TEXT NULL,
	"AntiDetectionStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ANTIDETECTIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTIDETECTIONTACTICALOBJECTIVE"(
	"AntiDetectionTacticalObjectiveID" INTEGER NOT NULL,
	"AntiDetectionTacticalObjectiveName" TEXT NULL,
	"AntiDetectionTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ANTIREMOVALSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTIREMOVALSTRATEGICOBJECTIVE"(
	"AntiRemovalStrategicObjectiveID" INTEGER NOT NULL,
	"AntiRemovalStrategicObjectiveName" TEXT NULL,
	"AntiRemovalStrategicObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ANTIREMOVALTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ANTIREMOVALTACTICALOBJECTIVE"(
	"AntiRemovalTacticalObjectiveID" INTEGER NOT NULL,
	"AntiRemovalTacticalObjectiveName" TEXT NULL,
	"AntiRemovalTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "API"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "API"(
	"APIID" INTEGER NOT NULL,
	"APIGUID" TEXT NULL,
	"APIName" TEXT NULL,
	"APIDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APICALL"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APICALL"(
	"APICallID" INTEGER NOT NULL
)

;
/****** Object:  Table "APIFUNCTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APIFUNCTION"(
	"APIFunctionID" INTEGER NOT NULL,
	"APIFunctionGUID" TEXT NULL,
	"APIID" INTEGER NOT NULL,
	"FunctionID" INTEGER NOT NULL,
	"Function_Name" TEXT NULL,
	"Normalized_Function_Name" TEXT NULL,
	"Address" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"APIFunctionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "APIMEMORYADDRESS"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APIMEMORYADDRESS"(
	"APIMemoryAddressID" INTEGER NOT NULL,
	"APIID" INTEGER NOT NULL,
	"MemoryAddressID" INTEGER NOT NULL,
	"FunctionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "APIPLATFORM"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APIPLATFORM"(
	"APIPlatformID" INTEGER NOT NULL,
	"APIID" INTEGER NOT NULL,
	"PlatformID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATION"(
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"ApplicationName" TEXT NOT NULL,
	"ApplicationDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONAUTHENTICATIONTYPE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONAUTHENTICATIONTYPE"(
	"ApplicationAuthenticationTypeID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NULL,
	"ApplicationGUID" TEXT NULL,
	"AuthenticationTypeID" INTEGER NULL,
	"AuthenticationTypeGUID" TEXT NULL,
	"AuthenticationRank" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ApplicationAuthenticationTypeDescription" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONBLACKLIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONBLACKLIST"(
	"ApplicationBlacklistID" INTEGER NOT NULL
)

;
/****** Object:  Table "APPLICATIONCATEGORIES"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONCATEGORIES"(
	"ApplicationCategoriesID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"ApplicationCategoryID" INTEGER NOT NULL,
	"ApplicationCategoryGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONCATEGORY"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONCATEGORY"(
	"ApplicationCategoryID" INTEGER NOT NULL,
	"ApplicationCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"ApplicationCategoryName" TEXT NULL,
	"ApplicationCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONCRITICALITY"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONCRITICALITY"(
	"ApplicationCriticalityID" INTEGER NOT NULL,
	"ApplicationCriticalityDescription" TEXT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"ApplicationCriticalityLevelID" INTEGER NOT NULL,
	"ApplicationCriticalityLevelGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONCRITICALITYLEVEL"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONCRITICALITYLEVEL"(
	"ApplicationCriticalityLevelID" INTEGER NOT NULL
)

;
/****** Object:  Table "APPLICATIONDEPENDENCY"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONDEPENDENCY"(
	"ApplicationDependencyID" INTEGER NOT NULL,
	"ApplicationParentID" INTEGER NULL,
	"ApplicationParentGUID" TEXT NULL,
	"ApplicationSubjectID" INTEGER NULL,
	"ApplicationSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONDOCUMENT"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONDOCUMENT"(
	"ApplicationDocumentID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NULL,
	"ApplicationGUID" TEXT NULL,
	"DocumentID" INTEGER NULL,
	"DocumentGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONFILEEXTENSIONBLACKLIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONFILEEXTENSIONBLACKLIST"(
	"ApplicationFileExtensionBlacklistID" INTEGER NOT NULL
)

;
/****** Object:  Table "APPLICATIONFILEEXTENSIONWHITELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONFILEEXTENSIONWHITELIST"(
	"ApplicationFileExtensionWhitelistID" INTEGER NOT NULL
)

;
/****** Object:  Table "APPLICATIONFILELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONFILELIST"(
	"ApplicationFileListID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NULL,
	"ApplicationGUID" TEXT NULL,
	"ApplicationFileListRelationship" TEXT NULL,
	"ApplicationFileListDescription" TEXT NULL,
	"FileListID" INTEGER NULL,
	"FileListGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONFORASSET"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONFORASSET"(
	"AssetApplicationID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "APPLICATIONFORORGANISATION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONFORORGANISATION"(
	"OrganisationApplicationID" INTEGER NOT NULL,
	"OrganisationApplicationGUID" TEXT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"OrganisationGUID" TEXT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "APPLICATIONFUNCTION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONFUNCTION"(
	"ApplicationFunctionID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"FunctionID" INTEGER NOT NULL,
	"FunctionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONMIMEWHITELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONMIMEWHITELIST"(
	"ApplicationMIMEWhitelistID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"MIMEWhitelistID" INTEGER NOT NULL,
	"MIMEWhitelistGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONNETWORKZONE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONNETWORKZONE"(
	"NetworkZoneApplicationID" INTEGER NOT NULL,
	"NetworkZoneID" INTEGER NULL,
	"NetworkZoneGUID" TEXT NULL,
	"ApplicationID" INTEGER NULL,
	"ApplicationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONPERSON"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONPERSON"(
	"AppPersonID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonGUID" TEXT NULL,
	"Usage" TEXT NULL,
	"Description" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONPORTWHITELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONPORTWHITELIST"(
	"ApplicationPortWhitelistID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NULL,
	"ApplicationGUID" TEXT NULL,
	"PortID" INTEGER NULL,
	"inboundaccepted" INTEGER NULL,
	"outboundaccepted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONSECURITYLABEL"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONSECURITYLABEL"(
	"ApplicationSecurityLabelID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"SecurityLabelID" INTEGER NOT NULL,
	"SecurityLabelGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONURI"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONURI"(
	"ApplicationURIID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"URIObjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONURIWHITELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONURIWHITELIST"(
	"ApplicationURIWhitelistID" INTEGER NOT NULL,
	"ApplicationURIID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidityID" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONVERSION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONVERSION"(
	"ApplicationVersionID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NULL,
	"ApplicationGUID" TEXT NULL,
	"VersionID" INTEGER NULL,
	"ApplicationVersionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "APPLICATIONWHITELIST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPLICATIONWHITELIST"(
	"ApplicationWhitelistID" INTEGER NOT NULL
)

;
/****** Object:  Table "APPROBATION"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPROBATION"(
	"ApprobationID" INTEGER NOT NULL
)

;
/****** Object:  Table "APPROVAL"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "APPROVAL"(
	"ApprovalID" INTEGER NOT NULL,
	"ApprobationID" INTEGER NULL
)

;
/****** Object:  Table "ARCHITECTURALPARADIGM"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARCHITECTURALPARADIGM"(
	"ArchitecturalParadigmID" INTEGER NOT NULL,
	"ArchitecturalParadigmGUID" TEXT NULL,
	"ArchitecturalParadigmName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ARCHITECTURALPARADIGMFORTECHNICALCONTEXT"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARCHITECTURALPARADIGMFORTECHNICALCONTEXT"(
	"TechnicalContextArchitecturalParadigmID" INTEGER NOT NULL,
	"ArchitecturalParadigmID" INTEGER NOT NULL,
	"TechnicalContextID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ARCHIVEFILE"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARCHIVEFILE"(
	"ArchiveFileID" INTEGER NOT NULL,
	"FileID" INTEGER NULL,
	"ArchiveFileDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ARFASSET"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFASSET"(
	"ARFAssetID" INTEGER NOT NULL,
	"ARFAssetUID" TEXT NOT NULL,
	"AssetID" INTEGER NULL,
	"ReferenceID" INTEGER NULL
)

;
/****** Object:  Table "ARFASSETFORASSETS"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFASSETFORASSETS"(
	"AssetsID" INTEGER NOT NULL,
	"ARFAssetID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFEXTENDEDINFO"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFEXTENDEDINFO"(
	"ARFExtendedInfoID" INTEGER NOT NULL,
	"ExtendedInfoNCName" TEXT NOT NULL
)

;
/****** Object:  Table "ARFEXTENDEDINFOFORARFEXTENDEDINFOS"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFEXTENDEDINFOFORARFEXTENDEDINFOS"(
	"ARFExtendedInfosID" INTEGER NOT NULL,
	"ARFExtendedInfoID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFEXTENDEDINFOS"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFEXTENDEDINFOS"(
	"ARFExtendedInfosID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFOBJECTREF"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFOBJECTREF"(
	"ARFObjectRefID" INTEGER NOT NULL,
	"ARFObjectRefUID" TEXT NOT NULL
)

;
/****** Object:  Table "ARFOBJECTREFARFASSET"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFOBJECTREFARFASSET"(
	"ARFObjectRefID" INTEGER NOT NULL,
	"ARFAssetID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFOBJECTREFREPORT"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFOBJECTREFREPORT"(
	"ARFObjectRefID" INTEGER NOT NULL,
	"ReportID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFOBJECTREFREPORTREQUEST"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFOBJECTREFREPORTREQUEST"(
	"ARFObjectRefID" INTEGER NOT NULL,
	"ReportRequestID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFRELATIONSHIP"    Script Date: 04/03/2015 19:59:08 ******/

;

;
CREATE TABLE "ARFRELATIONSHIP"(
	"ARFRelationshipID" INTEGER NOT NULL,
	"RelationshipTypeQName" TEXT NOT NULL,
	"RelationshipTypeID" INTEGER NULL,
	"RelationshipScope" TEXT NULL,
	"RelationshipSubjectNCName" TEXT NOT NULL
)

;
/****** Object:  Table "ARFRELATIONSHIPARFASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARFRELATIONSHIPARFASSET"(
	"ARFRelationshipID" INTEGER NOT NULL,
	"ARFAssetID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFRELATIONSHIPFORARFRELATIONSHIPS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARFRELATIONSHIPFORARFRELATIONSHIPS"(
	"ARFRelationshipsID" INTEGER NOT NULL,
	"ARFRelationshipID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFRELATIONSHIPREPORT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARFRELATIONSHIPREPORT"(
	"ARFRelationshipID" INTEGER NOT NULL,
	"ReportID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFRELATIONSHIPREPORTREQUEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARFRELATIONSHIPREPORTREQUEST"(
	"ARFRelationshipID" INTEGER NOT NULL,
	"ReportRequestID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARFRELATIONSHIPS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARFRELATIONSHIPS"(
	"ARFRelationshipsID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARITHMETICFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARITHMETICFUNCTION"(
	"ArithmeticFunctionID" INTEGER NOT NULL,
	"ArithmeticOperationName" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ARITHMETICOPERATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARITHMETICOPERATION"(
	"ArithmeticOperationID" INTEGER NOT NULL,
	"ArithmeticOperationName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ARPCACHE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARPCACHE"(
	"ARPCacheID" INTEGER NOT NULL,
	"ARPCacheGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ARPCACHECHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARPCACHECHANGERECORD"(
	"ARPCacheChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARPCACHEENTRIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARPCACHEENTRIES"(
	"ARPCacheEntriesID" INTEGER NOT NULL,
	"ARPCacheID" INTEGER NOT NULL,
	"ARPCacheEntryID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL,
	"SuspectedMaliciousReasonGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ARPCACHEENTRY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARPCACHEENTRY"(
	"ARPCacheEntryID" INTEGER NOT NULL,
	"ARPCacheEntryGUID" TEXT NULL,
	"IP_Address" INTEGER NULL,
	"Physical_Address" TEXT NULL,
	"ARPCacheEntryTypeID" INTEGER NULL,
	"Network_Interface" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ARPCACHEENTRYTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARPCACHEENTRYTYPE"(
	"ARPCacheEntryTypeID" INTEGER NOT NULL,
	"ARPCacheEntryTypeName" TEXT NULL,
	"ARPCacheEntryTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ARTIFACT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARTIFACT"(
	"ArtifactID" INTEGER NOT NULL,
	"ArtifactGUID" TEXT NULL,
	"HashListID" INTEGER NULL,
	"Raw_Artifact" TEXT NULL,
	"RawArtifactID" INTEGER NULL,
	"Raw_Artifact_Reference" TEXT NULL,
	"ArtifactTypeID" INTEGER NOT NULL,
	"ArtifactTypeGUID" TEXT NULL,
	"content_type" TEXT NULL,
	"content_type_version" TEXT NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL,
	"SuspectedMaliciousReasonGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ARTIFACTCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARTIFACTCHANGERECORD"(
	"ArtifactChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "ARTIFACTHASHVALUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARTIFACTHASHVALUE"(
	"ArtifactHashValueID" INTEGER NOT NULL,
	"ArtifactID" INTEGER NOT NULL,
	"ArtifactGUID" TEXT NULL,
	"HashValueID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ARTIFACTPACKAGING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARTIFACTPACKAGING"(
	"ArtifactPackagingID" INTEGER NOT NULL,
	"ArtifactPackagingGUID" TEXT NULL,
	"ArtifactID" INTEGER NOT NULL,
	"ArtifactGUID" TEXT NULL,
	"PackagingID" INTEGER NOT NULL,
	"PackagingGUID" TEXT NULL,
	"is_encrypted" INTEGER NULL,
	"is_compressed" INTEGER NULL,
	"ArtifactPackagingDescription" TEXT NULL,
	"CollectedDate" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"RepositoryGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ARTIFACTTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ARTIFACTTYPE"(
	"ArtifactTypeID" INTEGER NOT NULL,
	"ArtifactTypeGUID" TEXT NULL,
	"ArtifactTypeName" TEXT NULL,
	"ArtifactTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ImportanceID" INTEGER NULL
)

;
/****** Object:  Table "ASN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASN"(
	"ASNID" INTEGER NOT NULL,
	"AddressID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ASOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASOBJECT"(
	"ASObjectID" INTEGER NOT NULL,
	"ASNumber" INTEGER NULL,
	"ASName" TEXT NULL,
	"ASHandle" TEXT NULL,
	"Regional_Internet_Registry" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "aspnet_Applications"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_Applications"(
	"ApplicationName" TEXT NOT NULL,
	"LoweredApplicationName" TEXT NOT NULL,
	"ApplicationId" TEXT NOT NULL,
	"Description" TEXT NULL
)

;
/****** Object:  Table "aspnet_Membership"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_Membership"(
	"ApplicationId" TEXT NOT NULL,
	"UserId" TEXT NOT NULL,
	"Password" TEXT NOT NULL,
	"PasswordFormat" INTEGER NOT NULL,
	"PasswordSalt" TEXT NOT NULL,
	"MobilePIN" TEXT NULL,
	"Email" TEXT NULL,
	"LoweredEmail" TEXT NULL,
	"PasswordQuestion" TEXT NULL,
	"PasswordAnswer" TEXT NULL,
	"IsApproved" INTEGER NOT NULL,
	"IsLockedOut" INTEGER NOT NULL,
	"CreateDate" TEXT NOT NULL,
	"LastLoginDate" TEXT NOT NULL,
	"LastPasswordChangedDate" TEXT NOT NULL,
	"LastLockoutDate" TEXT NOT NULL,
	"FailedPasswordAttemptCount" INTEGER NOT NULL,
	"FailedPasswordAttemptWindowStart" TEXT NOT NULL,
	"FailedPasswordAnswerAttemptCount" INTEGER NOT NULL,
	"FailedPasswordAnswerAttemptWindowStart" TEXT NOT NULL,
	"Comment" TEXT NULL
)

;
/****** Object:  Table "aspnet_Paths"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_Paths"(
	"ApplicationId" TEXT NOT NULL,
	"PathId" TEXT NOT NULL,
	"Path" TEXT NOT NULL,
	"LoweredPath" TEXT NOT NULL
)

;
/****** Object:  Table "aspnet_PersonalizationAllUsers"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_PersonalizationAllUsers"(
	"PathId" TEXT NOT NULL,
	"PageSettings" BLOB NOT NULL,
	"LastUpdatedDate" TEXT NOT NULL
)

;
/****** Object:  Table "aspnet_PersonalizationPerUser"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_PersonalizationPerUser"(
	"Id" TEXT NOT NULL,
	"PathId" TEXT NULL,
	"UserId" TEXT NULL,
	"PageSettings" BLOB NOT NULL,
	"LastUpdatedDate" TEXT NOT NULL
)

;
/****** Object:  Table "aspnet_Profile"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_Profile"(
	"UserId" TEXT NOT NULL,
	"PropertyNames" TEXT NOT NULL,
	"PropertyValuesString" TEXT NOT NULL,
	"PropertyValuesBinary" BLOB NOT NULL,
	"LastUpdatedDate" TEXT NOT NULL
)

;
/****** Object:  Table "aspnet_Roles"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_Roles"(
	"ApplicationId" TEXT NOT NULL,
	"RoleId" TEXT NOT NULL,
	"RoleName" TEXT NOT NULL,
	"LoweredRoleName" TEXT NOT NULL,
	"Description" TEXT NULL
)

;
/****** Object:  Table "aspnet_SchemaVersions"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_SchemaVersions"(
	"Feature" TEXT NOT NULL,
	"CompatibleSchemaVersion" TEXT NOT NULL,
	"IsCurrentVersion" INTEGER NOT NULL
)

;
/****** Object:  Table "aspnet_Users"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_Users"(
	"ApplicationId" TEXT NOT NULL,
	"UserId" TEXT NOT NULL,
	"UserName" TEXT NOT NULL,
	"LoweredUserName" TEXT NOT NULL,
	"MobileAlias" TEXT NULL,
	"IsAnonymous" INTEGER NOT NULL,
	"LastActivityDate" TEXT NOT NULL
)

;
/****** Object:  Table "aspnet_UsersInRoles"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "aspnet_UsersInRoles"(
	"UserId" TEXT NOT NULL,
	"RoleId" TEXT NOT NULL
)

;
/****** Object:  Table "aspnet_WebEvent_Events"    Script Date: 04/03/2015 19:59:09 ******/

;

;

;
CREATE TABLE "aspnet_WebEvent_Events"(
	"EventId" TEXT NOT NULL,
	"EventTimeUtc" TEXT NOT NULL,
	"EventTime" TEXT NOT NULL,
	"EventType" TEXT NOT NULL,
	"EventSequence" REAL NOT NULL,
	"EventOccurrence" REAL NOT NULL,
	"EventCode" INTEGER NOT NULL,
	"EventDetailCode" INTEGER NOT NULL,
	"Message" TEXT NULL,
	"ApplicationPath" TEXT NULL,
	"ApplicationVirtualPath" TEXT NULL,
	"MachineName" TEXT NOT NULL,
	"RequestUrl" TEXT NULL,
	"ExceptionType" TEXT NULL,
	"Details" TEXT NULL
)

;

;
/****** Object:  Table "ASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSET"(
	"AssetID" INTEGER PRIMARY KEY,
	"AssetGUID" TEXT NULL,
	"AssetName" TEXT NULL,
	"AssetDescription" TEXT NULL,
	"AssetCriticalityLevel" TEXT NULL,
	"TaskCriticalAsset" INTEGER NULL,
	"DefenseCriticalAsset" INTEGER NULL,
	"OSName" TEXT NULL,
	"Enabled" INTEGER NULL,
	BLOB TEXT NULL,
	"LastCheckedDate" TEXT NULL,
	"X500name" TEXT NULL,
	"fqdn" TEXT NULL,
	"hostname" TEXT NULL,
	"motherboardguid" TEXT NULL,
	"instancename" TEXT NULL,
	"networkname" TEXT NULL,
	"ipnetrangestartIPv4" TEXT NULL,
	"ipnetrangeendIPv4" TEXT NULL,
	"ipnetrangestartIPv6" TEXT NULL,
	"ipnetrangeendIPv6" TEXT NULL,
	"cidr" TEXT NULL,
	"websiteurl" TEXT NULL,
	"documentroot" TEXT NULL,
	"locale" TEXT NULL,
	"installationid" TEXT NULL,
	"license" TEXT NULL,
	"systemname" TEXT NULL,
	"version" TEXT NULL,
	"ipaddressIPv4" TEXT NULL,
	"ipaddressIPv6" TEXT NULL,
	"subnetmaskIPv4" TEXT NULL,
	"subnetmaskIPv6" TEXT NULL,
	"defaultrouteIPv4" TEXT NULL,
	"defaultrouteIPv6" TEXT NULL,
	"personal" INTEGER NULL,
	"managedbythirdparty" INTEGER NULL,
	"hostedbythirdparty" INTEGER NULL,
	"notes" TEXT NULL,
	"cloud" TEXT NULL,
	"AssetManagementID" INTEGER NULL,
	"AssetOwnershipID" INTEGER NULL,
	"AssetLocationID" INTEGER NULL,
	"virtual" INTEGER NULL,
	"ADParticipation" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "ASSETADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETADDRESS"(
	"AssetAddressID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"AddressID" INTEGER NOT NULL,
	"AddressGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETARPCACHE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETARPCACHE"(
	"AssetARPCacheID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"ARPCacheID" INTEGER NULL,
	"ARPCacheGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETBLACKLIST"(
	"AssetBlacklistID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"OrganisationGUID" TEXT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETCERTIFICATE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETCERTIFICATE"(
	"AssetCertificateID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"CertificateID" INTEGER NOT NULL,
	"CertificateGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"AssetCertificateDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETCERTIFICATEORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETCERTIFICATEORGANISATION"(
	"AssetCertificateOrganisationID" INTEGER NOT NULL,
	"AssetCertificateID" INTEGER NOT NULL,
	"AssetCertificateGUID" TEXT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"OrganisationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"AssetCertificateOrganisationDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETCHANGERECORD"(
	"AssetChangeRecordID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"ChangeRecordID" INTEGER NOT NULL,
	"ChangeRecordGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETCREDENTIAL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETCREDENTIAL"(
	"AssetCredentialID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"AuthenticationTypeID" INTEGER NULL,
	"AuthenticationTypeGUID" TEXT NULL,
	"AuthenticationType" TEXT NULL,
	"Username" TEXT NULL,
	"Password" TEXT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"OrganisationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETCRITICALITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETCRITICALITYLEVEL"(
	"AssetCriticalityLevelID" INTEGER NOT NULL,
	"AssetCriticalityLevelGUID" TEXT NULL,
	"CriticalityLevelID" INTEGER NULL,
	"AssetCriticalityLevelName" TEXT NULL,
	"AssetCriticalityLevelDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETCRITICALITYLEVELFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETCRITICALITYLEVELFORASSET"(
	"AssetCriticalityID" INTEGER NOT NULL,
	"AssetCriticalityDescription" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetCriticalityLevelID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETDEVICE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETDEVICE"(
	"AssetDeviceID" INTEGER NOT NULL,
	"AssetDeviceGUID" TEXT NULL,
	"AssetDeviceDescription" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"DeviceID" INTEGER NOT NULL,
	"DeviceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETFORASSET"(
	"AssetForAssetID" INTEGER NOT NULL,
	"AssetRefID" INTEGER NOT NULL,
	"AssetRefGUID" TEXT NULL,
	"AssetRelationshipID" INTEGER NULL,
	"relationshiptype" TEXT NULL,
	"relationshipscope" TEXT NULL,
	"AssetSubjectID" INTEGER NOT NULL,
	"AssetSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETFORORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETFORORGANISATION"(
	"AssetForOrganisationID" INTEGER NOT NULL,
	"OrganisationAssetGUID" TEXT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"OrganisationGUID" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"Relationship" TEXT NULL
)

;
/****** Object:  Table "ASSETFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETFORTHREATACTORTTP"(
	"AssetForThreatActorTTPID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"ThreatActorTTPGUID" TEXT NULL,
	"Information_Source" TEXT NULL,
	"ConfidenceLevel" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"notes" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETFUNCTION"(
	"AssetFunctionID" INTEGER NOT NULL,
	"AssetFunctionName" TEXT NOT NULL,
	"AssetFunctionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETFUNCTIONFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETFUNCTIONFORASSET"(
	"AssetAssetFunctionID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetFunctionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETGEOLOCATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETGEOLOCATION"(
	"AssetGeoLocationID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"GeoLocationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"CollectionTimestamp" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETGROUP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETGROUP"(
	"AssetGroupID" INTEGER NOT NULL,
	"AssetGroupGUID" TEXT NULL,
	"AssetForAssetID" INTEGER NULL,
	"AssetGroupName" TEXT NULL,
	"AssetGroupDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"OrganisationID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETINFORMATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETINFORMATION"(
	"AssetInformationID" INTEGER NOT NULL,
	"hostname" TEXT NULL,
	"netbios" TEXT NULL,
	"hosttype" TEXT NULL,
	"JobID" INTEGER NOT NULL,
	"information" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ASSETLICENSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETLICENSE"(
	"AssetLicenseID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"LicenseNumber" TEXT NULL,
	"LicenseValue" REAL NULL,
	"LicenseID" INTEGER NULL,
	"LicenseFileID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETLOCATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETLOCATION"(
	"AssetLocationID" INTEGER NOT NULL,
	"AssetLocationType" TEXT NOT NULL,
	"AssetLocationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ASSETLOCATIONFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETLOCATIONFORASSET"(
	"AssetLocationTimeID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetLocationID" INTEGER NOT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETMANAGEMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETMANAGEMENT"(
	"AssetManagementID" INTEGER NOT NULL,
	"ManagementID" INTEGER NULL,
	"ManagementType" TEXT NOT NULL,
	"ManagementDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETMANAGEMENTFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETMANAGEMENTFORASSET"(
	"AssetManagementTimeID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetManagementID" INTEGER NOT NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETMEMORYDUMP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETMEMORYDUMP"(
	"AssetMemoryDumpID" INTEGER NOT NULL
)

;
/****** Object:  Table "ASSETNETWORKZONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETNETWORKZONE"(
	"AssetNetworkZoneID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"NetworkZoneID" INTEGER NULL,
	"NetworkZoneGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"LastCheckedDate" TEXT NULL,
	"ConfidentialityLevelID" INTEGER NULL
)

;
/****** Object:  Table "ASSETNETWORKZONERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETNETWORKZONERESTRICTION"(
	"AssetNetworkZoneRestrictionID" INTEGER NOT NULL,
	"AssetNetworkZoneRestrictionDescription" TEXT NULL,
	"AssetNetworkZoneID" INTEGER NOT NULL,
	"AssetNetworkZoneGUID" TEXT NULL,
	"RestrictionID" INTEGER NOT NULL,
	"CreationDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "ASSETORGANIZATIONALUNIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETORGANIZATIONALUNIT"(
	"AssetOrganizationalUnitID" INTEGER NOT NULL,
	"OrganizationalUnitID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETOWNERSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETOWNERSHIP"(
	"AssetOwnershipID" INTEGER NOT NULL,
	"OwnershipID" INTEGER NULL,
	"OwnershipName" TEXT NOT NULL,
	"OwnershipDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ASSETPERIMETER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETPERIMETER"(
	"AssetPerimeterID" INTEGER NOT NULL,
	"AssetPerimeterGUID" TEXT NULL
)

;
/****** Object:  Table "ASSETPERIMETERASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETPERIMETERASSET"(
	"AssetPerimeterAssetID" INTEGER NOT NULL
)

;
/****** Object:  Table "ASSETPERIMETERNETWORKZONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETPERIMETERNETWORKZONE"(
	"AssetPerimeterNetworkZoneID" INTEGER NOT NULL
)

;
/****** Object:  Table "ASSETPERIMETERSECURITYCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETPERIMETERSECURITYCONTROL"(
	"AssetPerimeterSecurityControlID" INTEGER NOT NULL
)

;
/****** Object:  Table "ASSETPHYSICALLOCATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETPHYSICALLOCATION"(
	"AssetPhysicalLocationTimeID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"PhysicalLocationID" INTEGER NOT NULL,
	BLOB TEXT NULL,
	"InformationPersonID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETPLATFORM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETPLATFORM"(
	"AssetPlatformID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"PlatformID" INTEGER NULL,
	"PlatformGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"LastCheckedDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETPRODUCT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETPRODUCT"(
	"AssetProductID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"ProductID" INTEGER NOT NULL,
	"ProductGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"LastCheckedDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETRELATIONSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETRELATIONSHIP"(
	"AssetRelationshipID" INTEGER NOT NULL,
	"relationshiptype" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETREPORTCOLLECTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETREPORTCOLLECTION"(
	"AssetReportCollectionID" INTEGER NOT NULL,
	"ARFReportCollectionID" TEXT NULL,
	"ReportRequestsID" INTEGER NULL,
	"AssetsID" INTEGER NULL,
	"ReportsID" INTEGER NULL,
	"ARFRelationshipsID" INTEGER NULL,
	"ARFExtendedInfosID" INTEGER NULL
)

;
/****** Object:  Table "ASSETRISKRATING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETRISKRATING"(
	"AssetRiskRatingID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"RiskRatingID" INTEGER NOT NULL,
	"AssetRiskRatingDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETROLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETROLE"(
	"AssetRoleID" INTEGER NOT NULL,
	"AssetRoleGUID" TEXT NULL,
	"AssetRoleName" TEXT NOT NULL,
	"AssetRoleDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETROLEFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETROLEFORASSET"(
	"AssetRoleForAssetID" INTEGER NOT NULL,
	"AssetAssetRoleGUID" TEXT NULL,
	"AssetRoleID" INTEGER NOT NULL,
	"AssetRoleGUID" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETS"(
	"AssetsID" INTEGER NOT NULL
)

;
/****** Object:  Table "ASSETSECURITYCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETSECURITYCONTROL"(
	"AssetSecurityControlID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"SecurityControlID" INTEGER NOT NULL,
	"SecurityControlGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "ASSETSENSOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETSENSOR"(
	"AssetSensorID" INTEGER NOT NULL,
	"AssetSensorGUID" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"SensorID" INTEGER NOT NULL,
	"SensorGUID" TEXT NULL,
	"AssetSensorName" TEXT NULL,
	"AssetSensorDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETSESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETSESSION"(
	"AssetSessionID" INTEGER NOT NULL,
	"AssetSessionGUID" TEXT NULL,
	"SessionID" INTEGER NULL,
	"SessionGUID" TEXT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ASSETSYNTHETICID"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETSYNTHETICID"(
	"AssetSyntheticID" INTEGER NOT NULL,
	"AssetSyntheticIDGUID" TEXT NULL,
	"resource" TEXT NOT NULL,
	"id" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ASSETSYNTHETICIDFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETSYNTHETICIDFORASSET"(
	"AssetAssetSyntheticID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"AssetSyntheticID" INTEGER NOT NULL,
	"AssetSyntheticIDGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ASSETTECHNOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETTECHNOLOGY"(
	"AssetTechnologyID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"TechnologyID" INTEGER NULL,
	"TechnologyGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETVALUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETVALUE"(
	"AssetValueID" INTEGER NOT NULL,
	"AssetValueName" TEXT NOT NULL,
	"AssetValueDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ASSETVALUEFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETVALUEFORASSET"(
	"AssetValueForAssetID" INTEGER NOT NULL,
	"AssetAssetValueGUID" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"AssetValueID" INTEGER NOT NULL,
	"AssetValueGUID" TEXT NULL,
	"ValueValue" REAL NULL,
	"iso_currency_code" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETVARIETY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETVARIETY"(
	"AssetVarietyID" INTEGER NOT NULL,
	"AssetVarietyName" TEXT NOT NULL,
	"AssetVarietyDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ASSETVARIETYFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETVARIETYFORASSET"(
	"AssetAssetVarietyID" INTEGER NOT NULL,
	"AssetVarietyID" INTEGER NOT NULL,
	"AssetVarietyGUID" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSETWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETWHITELIST"(
	"AssetWhitelistID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ASSETZONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSETZONE"(
	"AssetZoneID" INTEGER NOT NULL,
	"AssetZoneGUID" TEXT NULL,
	"AssetID" INTEGER NULL,
	"ZoneID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ASSOCIATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSOCIATION"(
	"AssociationID" INTEGER NOT NULL
)

;
/****** Object:  Table "ASSOCIATIONRULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSOCIATIONRULE"(
	"AssociationRuleID" INTEGER NOT NULL,
	"RuleID" INTEGER NULL
)

;
/****** Object:  Table "ASSURANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSURANCE"(
	"AssuranceID" INTEGER NOT NULL
)

;
/****** Object:  Table "ASSURANCEREQUIREMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ASSURANCEREQUIREMENT"(
	"AssuranceRequirementID" INTEGER NOT NULL,
	"RequirementID" INTEGER NULL,
	"RequirementGUID" TEXT NULL,
	"AssuranceRequirementGUID" TEXT NULL,
	"AssuranceRequirementTitle" TEXT NULL,
	"AssuranceRequirementDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACHMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ATTACHMENT"(
	"AttachmentID" INTEGER NOT NULL,
	"AttachmentGUID" TEXT NULL,
	"FileID" INTEGER NULL,
	"FileGUID" TEXT NULL,
	"MIMEID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACHMENTREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ATTACHMENTREFERENCE"(
	"AttachmentReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "ATTRIBUTE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ATTRIBUTE"(
	"AttributeID" INTEGER NOT NULL,
	"AttributeName" TEXT NULL,
	"AttributeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTRIBUTEVALUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ATTRIBUTEVALUE"(
	"AttributeValueID" INTEGER NOT NULL,
	"AttributeID" INTEGER NOT NULL,
	"AttributeValueName" TEXT NULL,
	"AttributeValueDescription" TEXT NULL,
	"AttributeValueType" TEXT NULL,
	"AttributeValue" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "AUDIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUDIT"(
	"AuditID" INTEGER NOT NULL,
	"ProjectID" INTEGER NULL
)

;
/****** Object:  Table "AUDITFINDING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUDITFINDING"(
	"AuditFindingID" INTEGER NOT NULL,
	"AuditID" INTEGER NOT NULL,
	"FindingID" INTEGER NOT NULL,
	"AuditProcedureID" INTEGER NULL,
	"AuditFindingName" TEXT NULL,
	"AuditFindingDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "AUDITLOGEVENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUDITLOGEVENT"(
	"AuditLogEventID" INTEGER NOT NULL
)

;
/****** Object:  Table "AUDITPROCEDURE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUDITPROCEDURE"(
	"AuditProcedureID" INTEGER NOT NULL,
	"AuditProcedureName" TEXT NULL,
	"AuditProcedureDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "AUTHENTICATIONTOKENPROTECTIONMECHANISM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUTHENTICATIONTOKENPROTECTIONMECHANISM"(
	"AuthenticationTokenProtectionMechanismID" INTEGER NOT NULL,
	"AuthenticationTokenProtectionMechanismGUID" TEXT NULL,
	"AuthenticationTokenProtectionMechanismName" TEXT NULL,
	"AuthenticationTokenProtectionMechanismDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "AUTHENTICATIONTOKENPROTECTIONMECHANISMBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUTHENTICATIONTOKENPROTECTIONMECHANISMBLACKLIST"(
	"AuthenticationTokenProtectionMechanismBlacklistID" INTEGER NOT NULL
)

;
/****** Object:  Table "AUTHENTICATIONTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUTHENTICATIONTYPE"(
	"AuthenticationTypeID" INTEGER NOT NULL,
	"AuthenticationTypeGUID" TEXT NULL,
	"AuthenticationTypeName" TEXT NULL,
	"AuthenticationTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "AUTHENTICATIONTYPEBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUTHENTICATIONTYPEBLACKLIST"(
	"AuthenticationTypeBlacklistID" INTEGER NOT NULL
)

;
/****** Object:  Table "AUTHENTICATIONTYPEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUTHENTICATIONTYPEDESCRIPTION"(
	"AuthenticationTypeDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "AUTHENTICATIONTYPEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUTHENTICATIONTYPEREFERENCE"(
	"AuthenticationTypeReferenceID" INTEGER NOT NULL,
	"AuthenticationTypeID" INTEGER NULL,
	"AuthenticationTypeGUID" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "AUTHOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AUTHOR"(
	"AuthorID" INTEGER NOT NULL,
	"AuthorName" TEXT NOT NULL,
	"PersonID" INTEGER NULL,
	"OrganisationID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "AVAILABILITYLOSSTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AVAILABILITYLOSSTYPE"(
	"AvailabilityLossTypeID" INTEGER NOT NULL,
	"AvailabilityLossTypeName" TEXT NULL,
	"AvailabilityLossTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "AVAILABILITYVIOLATIONPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AVAILABILITYVIOLATIONPROPERTIES"(
	"AvailabilityViolationPropertiesID" INTEGER NOT NULL,
	"AvailabilityViolationPropertiesName" TEXT NULL,
	"AvailabilityViolationPropertiesDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ieEncrypted" INTEGER NULL
)

;
/****** Object:  Table "AVAILABILITYVIOLATIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AVAILABILITYVIOLATIONSTRATEGICOBJECTIVE"(
	"AvailabilityViolationStrategicObjectiveID" INTEGER NOT NULL,
	"AvailabilityViolationStrategicObjectiveName" TEXT NULL,
	"AvailabilityViolationStrategicObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "AVAILABILITYVIOLATIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "AVAILABILITYVIOLATIONTACTICALOBJECTIVE"(
	"AvailabilityViolationTacticalObjectiveID" INTEGER NOT NULL,
	"AvailabilityViolationTacticalObjectiveName" TEXT NULL,
	"AvailabilityViolationTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "BANNER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BANNER"(
	"BannerID" INTEGER NOT NULL,
	"BannerGUID" TEXT NULL,
	"BannerName" TEXT NULL,
	"BannerDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "BANNERREGEX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BANNERREGEX"(
	"BannerRegexID" INTEGER NOT NULL,
	"BannerRegexGUID" TEXT NULL,
	"BannerID" INTEGER NOT NULL,
	"BannerGUID" TEXT NULL,
	"RegexID" INTEGER NOT NULL,
	"RegexGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "BEGINFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;

;
CREATE TABLE "BEGINFUNCTION"(
	"BeginFunctionID" INTEGER NOT NULL,
	"StartsWithCharacters" TEXT NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL
)

;

;
/****** Object:  Table "BEHAVIOMETRIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIOMETRIC"(
	"BehaviometricID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIOR"(
	"BehaviorID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIORACTIONCOMPOSITION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORACTIONCOMPOSITION"(
	"BehaviorActionCompositionID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIORALCHARACTERISTIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORALCHARACTERISTIC"(
	"BehavioralCharacteristicID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIORASSOCIATEDCODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORASSOCIATEDCODE"(
	"BehaviorAssociatedCodeID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIORCOLLECTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORCOLLECTION"(
	"BehaviorCollectionID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIORDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORDESCRIPTION"(
	"BehaviorDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIORDISCOVERYMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORDISCOVERYMETHOD"(
	"BehaviorDiscoveryMethodID" INTEGER NOT NULL,
	"BehaviorID" INTEGER NULL,
	"DiscoveryMethodID" INTEGER NULL
)

;
/****** Object:  Table "BEHAVIORIDMATCHINGPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORIDMATCHINGPATTERN"(
	"BehaviorIDPatternID" INTEGER NOT NULL,
	"BehaviorIDPatternGUID" TEXT NULL,
	"BehaviorID" INTEGER NOT NULL,
	"BehaviorGUID" TEXT NULL,
	"BehaviorIDMatchingPattern" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "BEHAVIORIDPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORIDPATTERN"(
	"BehaviorIDPatternID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIORPURPOSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORPURPOSE"(
	"BehaviorPurposeID" INTEGER NOT NULL
)

;
/****** Object:  Table "BEHAVIORRELATIONSHIPS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BEHAVIORRELATIONSHIPS"(
	"BehaviorRelationShipsID" INTEGER NOT NULL
)

;
/****** Object:  Table "BIOMETRIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BIOMETRIC"(
	"BiometricID" INTEGER NOT NULL
)

;
/****** Object:  Table "BREACH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BREACH"(
	"BreachID" INTEGER NOT NULL
)

;
/****** Object:  Table "BREACHDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BREACHDESCRIPTION"(
	"BreachDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "BREACHEVIDENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BREACHEVIDENCE"(
	"BreachEvidenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "BREACHFINDING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BREACHFINDING"(
	"BreachFindingID" INTEGER NOT NULL
)

;
/****** Object:  Table "BREACHNOTIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BREACHNOTIFICATION"(
	"BreachNotificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "BREACHTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BREACHTAG"(
	"BreachTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "BREAK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BREAK"(
	"BreakID" INTEGER NOT NULL
)

;
/****** Object:  Table "BROWSER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BROWSER"(
	"BrowserID" INTEGER NOT NULL,
	"SoftwareID" INTEGER NULL
)

;
/****** Object:  Table "BROWSERCHARACTERISTIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BROWSERCHARACTERISTIC"(
	"BrowserCharacteristicID" INTEGER NOT NULL
)

;
/****** Object:  Table "BULLETIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BULLETIN"(
	"BulletinID" INTEGER NOT NULL
)

;
/****** Object:  Table "BUSINESSIMPACT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BUSINESSIMPACT"(
	"BusinessImpactID" INTEGER NOT NULL,
	"BusinessImpactGUID" TEXT NULL,
	"ImpactLevel" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "BUSINESSIMPACTFORBUSINESSRISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BUSINESSIMPACTFORBUSINESSRISK"(
	"BusinessRiskBusinessImpactID" INTEGER NOT NULL,
	"BusinessImpactID" INTEGER NOT NULL,
	"BusinessImpactGUID" TEXT NULL,
	"BusinessRiskID" INTEGER NOT NULL,
	"BusinessRiskGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "BUSINESSIMPACTFORREGULATORYRISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BUSINESSIMPACTFORREGULATORYRISK"(
	"RegulatoryRiskBusinessImpactID" INTEGER NOT NULL,
	"BusinessImpactID" INTEGER NOT NULL,
	"BusinessImpactGUID" TEXT NULL,
	"RegulatoryRiskID" INTEGER NOT NULL,
	"RegulatoryRiskGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "BUSINESSPROCESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BUSINESSPROCESS"(
	"BusinessProcessID" INTEGER NOT NULL
)

;
/****** Object:  Table "BUSINESSRISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BUSINESSRISK"(
	"BusinessRiskID" INTEGER NOT NULL,
	"RiskDescription" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "BYTERUN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BYTERUN"(
	"ByteRunID" INTEGER NOT NULL,
	"Offset" INTEGER NULL,
	"File_System_Offset" INTEGER NULL,
	"Image_Offset" INTEGER NULL,
	"Length" INTEGER NULL,
	"HashListID" INTEGER NULL,
	"Byte_Run_Data" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "BYTERUNS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BYTERUNS"(
	"ByteRunsID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "BYTESRUNSBYTERUN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "BYTESRUNSBYTERUN"(
	"ByteRunsButeRunID" INTEGER NOT NULL,
	"ByteRunsID" INTEGER NOT NULL,
	"ByteRunID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "CAPABILITYOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CAPABILITYOBJECTIVE"(
	"CapabilityObjectiveID" INTEGER NOT NULL,
	"CapabilityObjectiveGUID" TEXT NULL,
	"ObjectiveID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CAPABILITYOBJECTIVERELATIONSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CAPABILITYOBJECTIVERELATIONSHIP"(
	"CapabilityObjectiveRelashionshipID" INTEGER NOT NULL,
	"CapabilityObjectiveRelashionshipName" TEXT NULL,
	"CapabilityObjectiveRelashionshipDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "CATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CATEGORY"(
	"CategoryID" INTEGER NOT NULL,
	"CategoryName" TEXT NOT NULL,
	"CategoryDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CATEGORYDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CATEGORYDESCRIPTION"(
	"CategoryDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "CATEGORYREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CATEGORYREFERENCE"(
	"CategoryReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "CATEGORYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CATEGORYTAG"(
	"CategoryTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "CCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCE"(
	"CCEID" INTEGER NOT NULL,
	"cce_id" TEXT NOT NULL,
	"platform" TEXT NULL,
	"PlatformID" INTEGER NULL,
	"modified" TEXT NULL,
	"description" TEXT NULL,
	"parameter" TEXT NULL,
	"technical_mechanism" TEXT NULL,
	"reference" TEXT NULL,
	"resource_id" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CreationObjectGUID" TEXT NULL,
	"SourceID" INTEGER NULL,
	"SourceGUID" TEXT NULL,
	"RepositoryID" INTEGER NULL,
	"RepositoryGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"VocabularyGUID" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ImportanceID" INTEGER NULL,
	"ImportanceGUID" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceLevelGUID" TEXT NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ConfidenceReasonGUID" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustLevelGUID" TEXT NULL,
	"TrustReasonID" INTEGER NULL,
	"TrustReasonGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCEFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCEFORASSET"(
	"AssetCCEID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"CCEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CCEFORCPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCEFORCPE"(
	"CPECCEID" INTEGER NOT NULL,
	"cce_id" TEXT NULL,
	"CCEID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCEFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCEFORTHREATACTORTTP"(
	"ThreatActorTTPCCEID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"CCEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCEPARAMETER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCEPARAMETER"(
	"CCEParameterID" INTEGER NOT NULL,
	"CCEParameterText" TEXT NOT NULL,
	"CCEParameterDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCEPARAMETERFORCCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCEPARAMETERFORCCE"(
	"CCECCEParameterID" INTEGER NOT NULL,
	"CCEID" INTEGER NULL,
	"CCEParameterID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCEPARAMETERTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCEPARAMETERTAG"(
	"CCEParameterTagID" INTEGER NOT NULL,
	"CCEParameterID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCEREFERENCE"(
	"CCEReferenceID" INTEGER NOT NULL,
	"resource_id" TEXT NOT NULL,
	"ReferenceText" TEXT NOT NULL,
	"ReferenceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCEREFERENCEFORCCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCEREFERENCEFORCCE"(
	"CCECCEReferenceID" INTEGER NOT NULL,
	"CCEReferenceID" INTEGER NOT NULL,
	"CCEID" INTEGER NULL,
	"cce_id" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCERESOURCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCERESOURCE"(
	"CCEResourceID" INTEGER NOT NULL,
	"resource_id" TEXT NOT NULL,
	"modified" TEXT NULL,
	"ResourceTitle" TEXT NULL,
	"ResourcePublisher" TEXT NULL,
	"issued" TEXT NULL,
	"ResourceVersion" TEXT NULL,
	"ResourceFormat" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCERESOURCEAUTHOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCERESOURCEAUTHOR"(
	"CCEResourceAuthorID" INTEGER NOT NULL,
	"CCEResourceID" INTEGER NOT NULL,
	"AuthorID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CCERESOURCEFORCCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCERESOURCEFORCCE"(
	"CCECCEResourceID" INTEGER NOT NULL,
	"CCEResourceID" INTEGER NOT NULL,
	"CCEID" INTEGER NULL,
	"cce_id" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCERESOURCEFORCCEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCERESOURCEFORCCEREFERENCE"(
	"CCEReferenceCCEResourceID" INTEGER NOT NULL,
	"CCEResourceID" INTEGER NOT NULL,
	"CCEReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CCETECHNICALMECHANISM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCETECHNICALMECHANISM"(
	"CCETechnicalMechanismID" INTEGER NOT NULL,
	"TechnicalMechanismText" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CCETECHNICALMECHANISMFORCCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCETECHNICALMECHANISMFORCCE"(
	"CCECCETechnicalMechanismID" INTEGER NOT NULL,
	"CCEID" INTEGER NULL,
	"CCETechnicalMechanismID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CCETECHNICALMECHANISMTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CCETECHNICALMECHANISMTAG"(
	"CCETechnicalMechanismTagID" INTEGER NOT NULL,
	"CCETechnicalMechanismID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CERTIFICATE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CERTIFICATE"(
	"CertificateID" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CERTIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CERTIFICATION"(
	"CertificationID" INTEGER NOT NULL,
	"CertificationGUID" TEXT NULL,
	"CertificationAcronym" TEXT NULL,
	"CertificationName" TEXT NOT NULL,
	"CertificationDescription" TEXT NULL,
	"lang" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "CERTIFICATIONSKILL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CERTIFICATIONSKILL"(
	"CertificationSkillID" INTEGER NOT NULL,
	"CertificationID" INTEGER NULL,
	"SkillID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CHANGECONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHANGECONTROL"(
	"ChangeControlID" INTEGER NOT NULL,
	"SecurityControlID" INTEGER NULL
)

;
/****** Object:  Table "CHANGELOGENTRYTYPEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHANGELOGENTRYTYPEENUM"(
	"ChangeLogEntryTypeEnumID" INTEGER NOT NULL,
	"ChangeLogEntryType" TEXT NULL,
	"ChangeLogEntryTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "CHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHANGERECORD"(
	"ChangeRecordID" INTEGER NOT NULL,
	"ChangeRecordGUID" TEXT NULL,
	"ChangedObjectGUID" TEXT NULL,
	"BeforeChange" TEXT NULL,
	"AfterChange" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CHANGEREQUEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHANGEREQUEST"(
	"ChangeRequestID" INTEGER NOT NULL,
	"ChangeRequestGUID" TEXT NULL,
	"ImportanceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"StatusID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CHANGEREQUESTAPPROVAL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHANGEREQUESTAPPROVAL"(
	"ChangeRequestApprovalID" INTEGER NOT NULL
)

;
/****** Object:  Table "CHANGEREQUESTCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHANGEREQUESTCHANGERECORD"(
	"ChangeRequestChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "CHAPTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHAPTER"(
	"ChapterID" INTEGER NOT NULL,
	"SectionID" INTEGER NULL
)

;
/****** Object:  Table "CHARACTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARACTER"(
	"CharacterID" INTEGER NOT NULL,
	"CharacterGUID" TEXT NULL,
	"CharacterValue" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CHARACTERBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARACTERBLACKLIST"(
	"CharacterBlacklistID" INTEGER NOT NULL,
	"CharacterID" INTEGER NOT NULL
)

;
/****** Object:  Table "CHARACTERENCODING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARACTERENCODING"(
	"CharacterEncodingID" INTEGER NOT NULL,
	"CharacterEncodingName" TEXT NOT NULL,
	"CharacterEncodingDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "CHARACTERISTIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARACTERISTIC"(
	"CharacteristicID" INTEGER NOT NULL
)

;
/****** Object:  Table "CHARACTERSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARACTERSET"(
	"CharacterSetID" INTEGER NOT NULL,
	"CharacterSetGUID" TEXT NULL,
	"CharacterSetName" TEXT NULL,
	"CharacterSetValue" TEXT NULL,
	"CharacterSetDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CHARACTERSETBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARACTERSETBLACKLIST"(
	"CharacterSetBlacklistID" INTEGER NOT NULL,
	"CharacterSetID" INTEGER NULL
)

;
/****** Object:  Table "CHARACTERSETWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARACTERSETWHITELIST"(
	"CharacterSetWhitelistID" INTEGER NOT NULL,
	"CharacterSetID" INTEGER NULL
)

;
/****** Object:  Table "CHARACTERWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARACTERWHITELIST"(
	"CharacterWhitelistID" INTEGER NOT NULL,
	"CharacterID" INTEGER NOT NULL
)

;
/****** Object:  Table "CHARSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHARSET"(
	"CharSetID" INTEGER NOT NULL,
	"CharacterSetID" INTEGER NULL
)

;
/****** Object:  Table "CHECKENUMERATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHECKENUMERATION"(
	"CheckEnumerationID" INTEGER NOT NULL,
	"EnumerationValue" TEXT NOT NULL,
	"EnumerationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CHECKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHECKLIST"(
	"ChecklistID" INTEGER NOT NULL,
	"Title" TEXT NULL,
	"Description" TEXT NULL,
	"AnswerSchemes" TEXT NULL,
	"ChecklistCategoryID" INTEGER NULL,
	"MethodologyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CHECKLISTANSWER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHECKLISTANSWER"(
	"AnswerID" INTEGER NOT NULL,
	"QuestionID" INTEGER NULL,
	"Answer" TEXT NULL,
	"AnswerComments" TEXT NULL,
	"AttachmentID" INTEGER NULL,
	"AttachmentData" BLOB NULL,
	"MIMEID" INTEGER NULL,
	"AttachmentMimeType" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL
)

;
/****** Object:  Table "CHECKLISTCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHECKLISTCATEGORY"(
	"ChecklistCategoryID" INTEGER NOT NULL,
	"CategoryID" INTEGER NULL,
	"Title" TEXT NULL,
	"ChecklistCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CHECKLISTCHAPTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHECKLISTCHAPTER"(
	"ChapterID" INTEGER NOT NULL,
	"Title" TEXT NULL,
	"ChecklistID" INTEGER NULL,
	"ParentChapterID" INTEGER NULL
)

;
/****** Object:  Table "CHECKLISTQUESTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHECKLISTQUESTION"(
	"QuestionID" INTEGER NOT NULL,
	"QuestionRefID" TEXT NULL,
	"Title" TEXT NULL,
	"LongName" TEXT NULL,
	"Description" TEXT NULL,
	"Target" TEXT NULL,
	"ChapterID" INTEGER NULL,
	"Tags" TEXT NULL,
	"lang" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CHECKLISTQUESTIONCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHECKLISTQUESTIONCATEGORY"(
	"QuestionCategoryID" INTEGER NOT NULL,
	"QuestionID" INTEGER NOT NULL,
	"CategoryID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CHECKLISTQUESTIONSECURITYCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CHECKLISTQUESTIONSECURITYCONTROL"(
	"QuestionSecurityControlID" INTEGER NOT NULL,
	"QuestionID" INTEGER NOT NULL,
	"SecurityControlID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CIAIMPACTFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CIAIMPACTFORATTACKPATTERN"(
	"AttackPatternCIAImpactID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternGUID" TEXT NULL,
	"Confidentiality_Impact" TEXT NULL,
	"Integrity_Impact" TEXT NULL,
	"Availability_Impact" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CLASSIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CLASSIFICATION"(
	"ClassificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "CLASSIFICATIONCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CLASSIFICATIONCATEGORY"(
	"ClassificationCategoryID" INTEGER NOT NULL,
	"ClassificationCategoryGUID" TEXT NULL,
	"ClassificationCategoryName" TEXT NULL,
	"ClassificationCategoryDescription" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CLASSIFICATIONLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CLASSIFICATIONLEVEL"(
	"ClassificationLevelID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CLASSIFICATIONRESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CLASSIFICATIONRESTRICTION"(
	"ClassificationRestrictionID" INTEGER NOT NULL,
	"ClassificationID" INTEGER NOT NULL,
	"RestrictionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CLUSTEREDGENODEPAIR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CLUSTEREDGENODEPAIR"(
	"ClusterEdgeNodePairID" INTEGER NOT NULL
)

;
/****** Object:  Table "COASTAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COASTAGE"(
	"COAStageID" INTEGER NOT NULL,
	"COAStageGUID" TEXT NULL,
	"COAStageName" TEXT NOT NULL,
	"COAStageDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODE"(
	"CodeID" INTEGER NOT NULL,
	"CodeGUID" TEXT NULL,
	"Block_Nature" TEXT NULL,
	"ScriptID" INTEGER NULL,
	"Description" TEXT NULL,
	"Type" TEXT NULL,
	"CodeTypeID" INTEGER NULL,
	"Purpose" TEXT NULL,
	"CodePurposeID" INTEGER NULL,
	"Code_Language" TEXT NULL,
	"CodeLanguageID" INTEGER NULL,
	"TargetedPlatformsID" INTEGER NULL,
	"Processor_Family" TEXT NULL,
	"Discovery_Method" TEXT NULL,
	"MeasureSourceID" INTEGER NULL,
	"Start_Address" TEXT NULL,
	"MemoryAddressID" INTEGER NULL,
	"Code_Segment" TEXT NULL,
	"Code_Segment_XOR" TEXT NULL,
	"CodeSegmentXORID" INTEGER NULL,
	"DigitalSignaturesID" INTEGER NULL,
	"Extracted_Features" TEXT NULL,
	"ExtractedFeaturesID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CODEFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODEFUNCTION"(
	"CodeFunctionID" INTEGER NOT NULL,
	"CodeFunctionGUID" TEXT NULL,
	"CodeID" INTEGER NULL,
	"CodeGUID" TEXT NULL,
	"FunctionID" INTEGER NULL,
	"FunctionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"LastCheckedDate" TEXT NULL
)

;
/****** Object:  Table "CODELANGUAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODELANGUAGE"(
	"CodeLanguageID" INTEGER NOT NULL,
	"LanguageID" INTEGER NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "CODELANGUAGES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODELANGUAGES"(
	"CodeLanguagesID" INTEGER NOT NULL,
	"CodeID" INTEGER NOT NULL,
	"LanguageID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CodeLanguageDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"DiscoveryMethodID" INTEGER NULL,
	"DiscoveryToolID" INTEGER NULL
)

;
/****** Object:  Table "CODELICENSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODELICENSE"(
	"CodeLicenseID" INTEGER NOT NULL
)

;
/****** Object:  Table "CODELINE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODELINE"(
	"CodeLineID" INTEGER NOT NULL,
	"CodeLineGUID" TEXT NULL,
	"LineOfCode" TEXT NULL,
	"KnownVulnerable" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "CODELINEFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODELINEFUNCTION"(
	"CodeLineFunctionID" INTEGER NOT NULL,
	"CodeLineID" INTEGER NOT NULL,
	"FunctionID" INTEGER NULL,
	"LanguageFunctionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "CODELINES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODELINES"(
	"CodeLinesID" INTEGER NOT NULL,
	"CodeID" INTEGER NOT NULL,
	"CodeLineID" INTEGER NOT NULL,
	"ordinal_position" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CODEPROCESSORTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODEPROCESSORTYPE"(
	"CodeProcessorTypeID" INTEGER NOT NULL,
	"CodeID" INTEGER NOT NULL,
	"ProcessorTypeID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "CODEPURPOSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODEPURPOSE"(
	"CodePurposeID" INTEGER NOT NULL,
	"CodePurposeEnumID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CODEPURPOSEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODEPURPOSEENUM"(
	"CodePurposeEnumID" INTEGER NOT NULL,
	"CodePurpose" TEXT NULL,
	"CodePurposeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "CODESEGMENTXOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODESEGMENTXOR"(
	"CodeSegmentXORID" INTEGER NOT NULL,
	"xor_pattern" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "CODETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODETYPE"(
	"CodeTypeID" INTEGER NOT NULL,
	"CodeTypeEnumID" INTEGER NULL
)

;
/****** Object:  Table "CODETYPEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CODETYPEENUM"(
	"CodeTypeEnumID" INTEGER NOT NULL,
	"CodeType" TEXT NULL,
	"CodeTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "COLLECTIONMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COLLECTIONMETHOD"(
	"CollectionMethodID" INTEGER NOT NULL,
	"CollectionMethodName" TEXT NULL,
	"MeasureSourceID" INTEGER NULL,
	"CollectionMethodDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COLLECTIONMETHODDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COLLECTIONMETHODDESCRIPTION"(
	"CollectionMethodDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "COLLECTIONMETHODREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COLLECTIONMETHODREFERENCE"(
	"CollectionMethodReferenceID" INTEGER NOT NULL,
	"CollectionMethodID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CollectionMethodDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "COLLECTIONMETHODTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COLLECTIONMETHODTAG"(
	"CollectionMethodTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "COLSTAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COLSTAGE"(
	"COLStageID" INTEGER NOT NULL
)

;
/****** Object:  Table "COMMAND"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMMAND"(
	"CommandID" INTEGER NOT NULL,
	"CommandName" TEXT NOT NULL,
	"CommandDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"KnownVulnerable" INTEGER NULL
)

;
/****** Object:  Table "COMMANDANDCONTROLPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMMANDANDCONTROLPROPERTIES"(
	"CommandandControlPropertiesID" INTEGER NOT NULL,
	"CommandandControlPropertiesName" TEXT NULL,
	"CommandandControlPropertiesDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "COMMANDANDCONTROLSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMMANDANDCONTROLSTRATEGICOBJECTIVE"(
	"CommandandControlStrategicObjectiveID" INTEGER NOT NULL,
	"CommandandControlStrategicObjectiveName" TEXT NULL,
	"CommandandControlStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COMMANDANDCONTROLTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMMANDANDCONTROLTACTICALOBJECTIVE"(
	"CommandandControlTacticalObjectiveID" INTEGER NOT NULL,
	"CommandandControlTacticalObjectiveName" TEXT NULL,
	"CommandandControlTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COMMANDS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMMANDS"(
	"CommandsID" INTEGER NOT NULL,
	"ScriptName" TEXT NOT NULL,
	"CommandsDescription" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "COMMONCAPABILITYPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMMONCAPABILITYPROPERTIES"(
	"CommonCapabilityPropertiesID" INTEGER NOT NULL,
	"CommonCapabilityPropertiesName" TEXT NULL,
	"CommonCapabilityPropertiesDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COMPLIANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPLIANCE"(
	"ComplianceID" INTEGER NOT NULL,
	"ComplianceGUID" TEXT NULL,
	"ComplianceName" TEXT NULL,
	"ComplianceVersion" TEXT NULL,
	"ComplianceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "COMPLIANCECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPLIANCECATEGORY"(
	"ComplianceCategoryID" INTEGER NOT NULL,
	"ComplianceCategoryName" TEXT NULL,
	"ComplianceCategoryDescription" TEXT NULL,
	"ComplianceID" INTEGER NULL,
	"ParentCategoryID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "COMPLIANCECERTIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPLIANCECERTIFICATION"(
	"ComplianceCertificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "COMPLIANCECHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPLIANCECHANGERECORD"(
	"ComplianceChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "COMPLIANCEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPLIANCEDESCRIPTION"(
	"ComplianceDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "COMPLIANCEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPLIANCEREFERENCE"(
	"ComplianceReferenceID" INTEGER NOT NULL,
	"ComplianceID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ComplianceReferenceDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "COMPLIANCETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPLIANCETAG"(
	"ComplianceTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "COMPONENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPONENT"(
	"ComponentID" INTEGER PRIMARY KEY,
	"ComponentGUID" TEXT NULL,
	"SbomID" INTEGER NULL,
	"Name" TEXT NULL,
	"Version" TEXT NULL,
	"ComponentType" TEXT NULL,
	"PURL" TEXT NULL,
	"CPE" TEXT NULL,
	"CPEID" INTEGER NULL,
	"Supplier" TEXT NULL,
	"Publisher" TEXT NULL,
	"Group" TEXT NULL,
	"License" TEXT NULL,
	"Hash" TEXT NULL,
	"BOMRef" TEXT NULL,
	"Scope" TEXT NULL,
	"Description" TEXT NULL,
	"AssetID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"TenantID" INTEGER NULL
)

;
/****** Object:  Table "SBOM" (Software Composition Analysis — CycloneDX/SPDX) ******/

;
CREATE TABLE "SBOM"(
	"SbomID" INTEGER PRIMARY KEY,
	"SbomGUID" TEXT NULL,
	"Name" TEXT NULL,
	"Format" TEXT NULL,
	"SpecVersion" TEXT NULL,
	"SerialNumber" TEXT NULL,
	"SubjectName" TEXT NULL,
	"SubjectVersion" TEXT NULL,
	"AssetID" INTEGER NULL,
	"ApplicationID" INTEGER NULL,
	"ComponentCount" INTEGER NULL,
	"VulnerableCount" INTEGER NULL,
	"LicenseCount" INTEGER NULL,
	"Source" TEXT NULL,
	"ToolName" TEXT NULL,
	"Notes" TEXT NULL,
	"PersonID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"TenantID" INTEGER NULL
)

;
/****** Object:  Table "COMPONENTDEPENDENCY" (SBOM dependency edges) ******/

;
CREATE TABLE "COMPONENTDEPENDENCY"(
	"DependencyID" INTEGER PRIMARY KEY,
	"SbomID" INTEGER NULL,
	"FromRef" TEXT NULL,
	"ToRef" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"TenantID" INTEGER NULL
)

;
/****** Object:  Table "COMPRESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPRESSION"(
	"CompressionID" INTEGER NOT NULL,
	"compression_mechanism" TEXT NULL,
	"compression_mechanism_ref" TEXT NULL,
	"CompressionDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COMPRESSIONMECHANISM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPRESSIONMECHANISM"(
	"CompressionMechanismID" INTEGER NOT NULL,
	"MechanismID" INTEGER NULL
)

;
/****** Object:  Table "COMPRESSIONMECHANISMDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPRESSIONMECHANISMDESCRIPTION"(
	"CompressionMechanismDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "COMPRESSIONMECHANISMTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPRESSIONMECHANISMTAG"(
	"CompressionMechanismTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "COMPRESSIONREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COMPRESSIONREFERENCE"(
	"CompressionReferenceID" INTEGER NOT NULL,
	"CompressionID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "CONCATFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONCATFUNCTION"(
	"ConcatFunctionID" INTEGER NOT NULL
)

;
/****** Object:  Table "CONDITION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONDITION"(
	"ConditionID" INTEGER NOT NULL,
	"ConditionName" TEXT NOT NULL,
	"ConditionDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CONDITIONAPPLICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONDITIONAPPLICATION"(
	"ConditionApplicationID" INTEGER NOT NULL,
	"ConditionApplicationName" TEXT NOT NULL,
	"ConditionApplicationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CONFIDENCELEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONFIDENCELEVEL"(
	"ConfidenceLevelID" INTEGER NOT NULL,
	"ConfidenceLevelGUID" TEXT NULL,
	"ConfidenceLevelName" TEXT NOT NULL,
	"ConfidenceLevelDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CONFIDENCEREASON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONFIDENCEREASON"(
	"ConfidenceReasonID" INTEGER NOT NULL,
	"ConfidenceReasonName" TEXT NULL,
	"ConfidenceReasonDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CONFIDENTIALITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONFIDENTIALITYLEVEL"(
	"ConfidentialityLevelID" INTEGER NOT NULL,
	"ClassificationID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CONNECTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONNECTION"(
	"ConnectionID" INTEGER NOT NULL,
	"ipaddressIPv4" TEXT NULL,
	"ipaddressIPv6" TEXT NULL,
	"macaddress" TEXT NULL,
	"subnetmaskIPv4" TEXT NULL,
	"subnetmaskIPv6" TEXT NULL,
	"defaultrouteIPv4" TEXT NULL,
	"defaultrouteIPv6" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CONNECTIONFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONNECTIONFORASSET"(
	"AssetConnectionID" INTEGER NOT NULL,
	"AssetConnectionGUID" TEXT NULL,
	"ConnectionID" INTEGER NOT NULL,
	"ConnectionGUID" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "CONTACT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTACT"(
	"ContactID" INTEGER NOT NULL,
	"ContactTypeID" INTEGER NULL
)

;
/****** Object:  Table "CONTACTTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTACTTYPE"(
	"ContactTypeID" INTEGER NOT NULL,
	"ContactTypeGUID" TEXT NULL,
	"ContactTypeName" TEXT NOT NULL,
	"ContactTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CONTENTENUMERATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTENTENUMERATION"(
	"ContentEnumerationID" INTEGER NOT NULL,
	"ContentEnumerationValue" TEXT NOT NULL,
	"ContentEnumerationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CONTEXT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTEXT"(
	"ContextID" INTEGER NOT NULL
)

;
/****** Object:  Table "CONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTROL"(
	"ControlID" INTEGER NOT NULL,
	"ControlGUID" TEXT NULL,
	"ControlName" TEXT NULL,
	"ControlDescription" TEXT NULL,
	"ReliabilityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL
)

;
/****** Object:  Table "CONTROLCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTROLCATEGORY"(
	"ControlCategoryID" INTEGER NOT NULL,
	"ControlCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CONTROLDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTROLDESCRIPTION"(
	"ControlDescriptionID" INTEGER NOT NULL,
	"ControlID" INTEGER NULL,
	"ControlGUID" TEXT NULL,
	"DescriptionID" INTEGER NULL,
	"DescriptionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CONTROLREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTROLREFERENCE"(
	"ControlReferenceID" INTEGER NOT NULL,
	"ControlID" INTEGER NULL,
	"ControlGUID" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CONTROLSTRENGTH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTROLSTRENGTH"(
	"ControlStrengthID" INTEGER NOT NULL,
	"ControlStrengthGUID" TEXT NULL,
	"ControlStrengthName" TEXT NULL,
	"ControlStrengthDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CONTROLTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CONTROLTAG"(
	"ControlTagID" INTEGER NOT NULL,
	"ControlID" INTEGER NULL,
	"ControlGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "COOKIE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIE"(
	"CookieID" INTEGER NOT NULL,
	"CookieGUID" TEXT NULL,
	"CookieNameValue" TEXT NULL,
	"CookieNameID" INTEGER NULL,
	"CookieNameGUID" TEXT NULL,
	"CookieValue" TEXT NULL,
	"CookieDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COOKIEAPPLICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIEAPPLICATION"(
	"CookieApplicationID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NULL,
	"ApplicationGUID" TEXT NULL,
	"CookieApplicationRelationship" TEXT NULL,
	"CookieApplicationDescription" TEXT NULL,
	"CookieID" INTEGER NULL,
	"CookieGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "COOKIECPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIECPE"(
	"CookieCPEID" INTEGER NOT NULL
)

;
/****** Object:  Table "COOKIEFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIEFILE"(
	"CookieFileID" INTEGER NOT NULL
)

;
/****** Object:  Table "COOKIENAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIENAME"(
	"CookieNameID" INTEGER NOT NULL,
	"CookieNameGUID" TEXT NULL,
	"CookieNameValue" TEXT NULL,
	"CookieNameDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COOKIENAMEAPPLICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIENAMEAPPLICATION"(
	"CookieNameApplicationID" INTEGER NOT NULL
)

;
/****** Object:  Table "COOKIENAMEORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIENAMEORGANISATION"(
	"CookieNameOrganisationID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"OrganisationGUID" TEXT NULL,
	"CookieNameOrganisationRelationship" TEXT NULL,
	"CookieNameOrganisationDescription" TEXT NULL,
	"CookieNameID" INTEGER NULL,
	"CookieNameGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COOKIENAMEPRODUCT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIENAMEPRODUCT"(
	"CookieNameProductID" INTEGER NOT NULL,
	"CookieNameID" INTEGER NULL,
	"ProductID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COOKIEPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIEPERSON"(
	"CookiePersonID" INTEGER NOT NULL
)

;
/****** Object:  Table "COOKIESECURITYCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COOKIESECURITYCONTROL"(
	"CookieSecurityControlID" INTEGER NOT NULL,
	"CookieID" INTEGER NULL,
	"CookieGUID" TEXT NULL,
	"CookieSecurityControlRelationship" TEXT NULL,
	"CookieSecurityControlDescription" TEXT NULL,
	"SecurityControlID" INTEGER NULL,
	"SecurityControlGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "COUNTFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COUNTFUNCTION"(
	"CountFunctionID" INTEGER NOT NULL
)

;
/****** Object:  Table "COUNTRY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COUNTRY"(
	"CountryID" INTEGER NOT NULL,
	"CountryGUID" TEXT NULL,
	"CountryCode" TEXT NOT NULL,
	"CountryName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromdate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "COUNTRYLAW"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COUNTRYLAW"(
	"CountryLawID" INTEGER NOT NULL,
	"CountryID" INTEGER NOT NULL,
	"LawID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "COUNTRYLOCALE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COUNTRYLOCALE"(
	"CountryLocaleID" INTEGER NOT NULL,
	"CountryID" INTEGER NOT NULL,
	"LocaleID" INTEGER NOT NULL
)

;
/****** Object:  Table "COUNTRYTELEPHONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COUNTRYTELEPHONE"(
	"CountryTelephoneID" INTEGER NOT NULL
)

;
/****** Object:  Table "COUNTRYZONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COUNTRYZONE"(
	"CountryZoneID" INTEGER NOT NULL
)

;
/****** Object:  Table "COURSEOFACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COURSEOFACTION"(
	"CourseOfActionID" INTEGER NOT NULL
)

;
/****** Object:  Table "COURSEOFACTIONTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COURSEOFACTIONTYPE"(
	"CourseOfActionTypeID" INTEGER NOT NULL,
	"CourseOfActionTypeGUID" TEXT NULL,
	"CourseOfActionTypeName" TEXT NULL,
	"CourseOfActionTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "COURSEOFLAW"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "COURSEOFLAW"(
	"CourseOfLawID" INTEGER NOT NULL
)

;
/****** Object:  Table "CPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPE"(
	"CPEID" INTEGER NOT NULL,
	"CPEName" TEXT NOT NULL,
	"CPETitle" TEXT NULL,
	"NVDID" INTEGER NULL,
	"ModificationDate" TEXT NULL,
	"Status" TEXT NULL,
	"CPEDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEBANNER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEBANNER"(
	"CPEBannerID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"BannerID" INTEGER NOT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"RepositoryID" INTEGER NULL,
	"CreationObjectID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEBLACKLIST"(
	"CPEBlacklistID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEFILELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEFILELIST"(
	"CPEFileListID" INTEGER NOT NULL,
	"CPEID" INTEGER NULL,
	"CPEName" TEXT NULL,
	"CPEFileListRelationship" TEXT NULL,
	"CPEFileListDescription" TEXT NULL,
	"FileListID" INTEGER NULL,
	"FileListGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CPEFORAPPLICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEFORAPPLICATION"(
	"ApplicationCPEID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"CPEID" INTEGER NOT NULL,
	"CreationDate" TEXT NULL,
	BLOB TEXT NULL,
	"LastCheckedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "CPEFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEFORASSET"(
	"AssetCPEID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"CPEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "CPEFORFIXACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEFORFIXACTION"(
	"FixActionCPEID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"FixActionID" INTEGER NOT NULL,
	"relationshiptype" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEFORORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEFORORGANISATION"(
	"OrganisationCPEID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"Usage" TEXT NULL,
	"Description" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	BLOB TEXT NULL,
	"LastCheckedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEFORPLATFORM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEFORPLATFORM"(
	"PlatformCPEID" INTEGER NOT NULL,
	"PlatformID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEFORPRODUCT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEFORPRODUCT"(
	"ProductCPEID" INTEGER NOT NULL,
	"ProductID" INTEGER NOT NULL,
	"ProductGUID" TEXT NULL,
	"CPEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEFORTOOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEFORTOOL"(
	"ToolCPEID" INTEGER NOT NULL,
	"ToolID" INTEGER NOT NULL,
	"ToolGUID" TEXT NULL,
	"CPEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEGOOGLEDORK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEGOOGLEDORK"(
	"CPEGoogleDorkID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"GoogleDorkID" INTEGER NOT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPELOGICALTEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPELOGICALTEST"(
	"CPELogicalTestID" INTEGER NOT NULL,
	"negate" INTEGER NULL,
	"OperatorEnumerationID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CPEPATCH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEPATCH"(
	"CPEPatchID" INTEGER NOT NULL,
	"CPEID" INTEGER NULL,
	"PatchID" INTEGER NULL,
	"PatchGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEPORT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEPORT"(
	"CPEPortID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"PortID" INTEGER NOT NULL,
	"CPEPortUsage" TEXT NULL,
	"CPEPortDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEREFERENCE"(
	"CPEReferenceID" INTEGER NOT NULL,
	"CPEID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPETAG"(
	"CPETagID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CPETECHNOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPETECHNOLOGY"(
	"CPETechnologyID" INTEGER NOT NULL
)

;
/****** Object:  Table "CPEURI"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEURI"(
	"CPEURIID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"URIObjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CPEWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CPEWHITELIST"(
	"CPEWhitelistID" INTEGER NOT NULL,
	"CPEID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"OrganisationGUID" TEXT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CREATIONOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CREATIONOBJECT"(
	"CreationObjectID" INTEGER NOT NULL,
	"CreationObjectGUID" TEXT NULL,
	"ObjectID" INTEGER NULL,
	"RecordGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"OrganisationGUID" TEXT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"AccountID" INTEGER NULL,
	"AccountGUID" TEXT NULL,
	"UserID" INTEGER NULL,
	"UserGUID" TEXT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"SensorID" INTEGER NULL,
	"SensorGUID" TEXT NULL,
	"ToolID" INTEGER NULL,
	"ToolGUID" TEXT NULL,
	"ToolFunctionID" INTEGER NULL,
	"ToolFunctionGUID" TEXT NULL,
	"ToolCodeID" INTEGER NULL,
	"ToolCodeGUID" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL
)

;
/****** Object:  Table "CREATIONOBJECTHASH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CREATIONOBJECTHASH"(
	"CreationObjectHashID" INTEGER NOT NULL,
	"CreationObjectID" INTEGER NOT NULL,
	"CreationObjectGUID" TEXT NULL,
	"CreationObjectHashValue" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreationDate" TEXT NULL
)

;
/****** Object:  Table "CREDENTIAL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CREDENTIAL"(
	"CredentialID" INTEGER NOT NULL,
	"AuthenticationTypeID" INTEGER NULL,
	"Username" TEXT NULL,
	"Password" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "CREDENTIALACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CREDENTIALACCESSRECORD"(
	"CredentialAccessRecordID" INTEGER NOT NULL,
	"CredentialID" INTEGER NOT NULL,
	"AccessRecordID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationRecordID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CREDENTIALREPOSITORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CREDENTIALREPOSITORY"(
	"CredentialRepositoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "CRITICALITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CRITICALITYLEVEL"(
	"CriticalityLevelID" INTEGER NOT NULL,
	"CriticalityLevelGUID" TEXT NULL,
	"CriticalityLevelName" TEXT NULL,
	"CriticalityLevelDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CUSTOMOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CUSTOMOBJECT"(
	"CustomObjectID" INTEGER NOT NULL
)

;
/****** Object:  Table "CWE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWE"(
	"CWEID" TEXT NOT NULL,
	"CWEGUID" TEXT NULL,
	"CWEName" TEXT NULL,
	"CWEStatus" TEXT NULL,
	"CWEAbstraction" TEXT NULL,
	"CWEDescriptionSummary" TEXT NULL,
	"CWEExtendedDescription" TEXT NULL,
	"CWECausalNature" TEXT NULL,
	"CWEBackgroundDetails" TEXT NULL,
	"Maintenance_Notes" TEXT NULL,
	"Relationship_Notes" TEXT NULL,
	"Terminology_Notes" TEXT NULL,
	"White_Box_Definitions" TEXT NULL,
	"Platform_Notes" TEXT NULL,
	"Other_Notes" TEXT NULL,
	"Research_Gaps" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CWEURL" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"CriticalityLevelID" INTEGER NULL
)

;
/****** Object:  Table "CWEAFFECTEDFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEAFFECTEDFUNCTION"(
	"CWEAffectedFunctionID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"FunctionID" INTEGER NOT NULL,
	"FunctionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEAFFECTEDRESOURCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEAFFECTEDRESOURCE"(
	"CWEAffectedResourceID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"AffectedResourceID" INTEGER NOT NULL,
	"AffectedResourceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEALTERNATETERM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEALTERNATETERM"(
	"CWEAlternateTermID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"AlternateTerm" TEXT NOT NULL,
	"AlternateTermDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEALTERNATETERMTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEALTERNATETERMTAG"(
	"CWEAlternateTermTagID" INTEGER NOT NULL,
	"CWEAlternateTermID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEARCHITECTURALPARADIGM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEARCHITECTURALPARADIGM"(
	"CWEArchitecturalParadigmID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"ArchitecturalParadigmID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEATTACKCONSEQUENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEATTACKCONSEQUENCE"(
	"CWEAttackConsequenceID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"CWEAttackConsequenceOrder" INTEGER NOT NULL,
	"Consequence_Note" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEATTACKCONSEQUENCESCOPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEATTACKCONSEQUENCESCOPE"(
	"CWEAttackConsequenceScopeID" INTEGER NOT NULL,
	"CWEAttackConsequenceID" INTEGER NULL,
	"AttackScopeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEATTACKCONSEQUENCETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEATTACKCONSEQUENCETAG"(
	"CWEAttackConsequenceTagID" INTEGER NOT NULL,
	"CWEAttackConsequenceID" INTEGER NULL,
	"TagID" INTEGER NULL
)

;
/****** Object:  Table "CWEATTACKTECHNICALIMPACT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEATTACKTECHNICALIMPACT"(
	"CWEAttackTechnicalImpactID" INTEGER NOT NULL,
	"CWEAttackConsequenceID" INTEGER NULL,
	"AttackTechnicalImpactID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEDEMONSTRATIVEEXAMPLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEDEMONSTRATIVEEXAMPLE"(
	"CWEDemonstrativeExampleID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"DemonstrativeExampleID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEDESCRIPTION"(
	"CWEDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "CWEDETECTIONMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEDETECTIONMETHOD"(
	"CWEDetectionMethodID" INTEGER NOT NULL,
	"CWEDetectionMethodGUID" TEXT NULL,
	"CWEID" TEXT NOT NULL,
	"CWEGUID" TEXT NULL,
	"DetectionMethodID" INTEGER NOT NULL,
	"DetectionMethodGUID" TEXT NULL,
	"CWEDetectionMethodDescription" TEXT NULL,
	"CWEDetectionMethodEffectiveness" TEXT NULL,
	"CWEDetectionMethodEffectivenessNotes" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWEEXPLOITATIONFACTOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEEXPLOITATIONFACTOR"(
	"CWEExploitationFactorID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"ExploitationFactorID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWEFOROWASPTOP10"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEFOROWASPTOP10"(
	"CWEOWASPTOP10ID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"OWASPTOP10ID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"Mapping_Fit" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEFUNCTIONALAREA"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEFUNCTIONALAREA"(
	"CWEFunctionalAreaID" INTEGER NOT NULL,
	"CWEFunctionalAreaGUID" TEXT NULL,
	"CWEID" TEXT NULL,
	"FunctionalAreaID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWELANGUAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWELANGUAGE"(
	"CWELanguageID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"LanguageID" INTEGER NOT NULL,
	"LanguageGUID" TEXT NULL,
	"Prevalence" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWELANGUAGECLASS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWELANGUAGECLASS"(
	"CWELanguageClassID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"LanguageClassID" INTEGER NOT NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CWEMODEOFINTRODUCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEMODEOFINTRODUCTION"(
	"CWEModeOfIntroductionID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"ModeOfIntroductionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWEMODEOFINTRODUCTIONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEMODEOFINTRODUCTIONTAG"(
	"CWEModeOfIntroductionTagID" INTEGER NOT NULL,
	"CWEModeOfIntroductionID" INTEGER NULL,
	"TagID" INTEGER NULL
)

;
/****** Object:  Table "CWEORDINALITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEORDINALITY"(
	"CWEOrdinalityID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"WeaknessOrdinality" TEXT NULL,
	"Ordinality_Description" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWEOS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEOS"(
	"CWEOSID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"Operating_System_Name" TEXT NULL,
	"Prevalence" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWEOSCLASS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEOSCLASS"(
	"CWEOSClassID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"OSClassID" INTEGER NULL,
	"Prevalence" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEREFERENCE"(
	"CWEReferenceID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"Reference_Section" TEXT NULL,
	"LocalReferenceID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CWERELATIONSHIPCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWERELATIONSHIPCATEGORY"(
	"CWERelationshipCategoryID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"RelationshipNature" TEXT NOT NULL,
	"RelationshipTargetCWEID" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWERELEVANTPROPERTY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWERELEVANTPROPERTY"(
	"CWERelevantPropertyID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"Relevant_Property" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "CWEREPOSITORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWEREPOSITORY"(
	"CWERepositoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "CWERESEARCHGAP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWERESEARCHGAP"(
	"CWEResearchGapID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"ResearchGapText" TEXT NULL,
	"ResearchGapTextClean" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWETAG"(
	"CWETagID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWETAXONOMYNODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWETAXONOMYNODE"(
	"CWETaxonomyNodeID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"TaxonomyNodeID" INTEGER NOT NULL,
	"Mapping_Fit" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "CWETECHNOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWETECHNOLOGY"(
	"CWETechnologyID" INTEGER NOT NULL,
	"CWEID" TEXT NULL,
	"TechnologyID" INTEGER NULL,
	"Prevalence" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "CWETHEORETICALNOTE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWETHEORETICALNOTE"(
	"CWETheoreticalNoteID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"TheoreticalNoteID" INTEGER NOT NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWETIMEOFINTRODUCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWETIMEOFINTRODUCTION"(
	"CWETimeOfIntroductionID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"PhaseID" INTEGER NULL,
	"IntroductoryPhase" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "CWETOP25"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "CWETOP25"(
	"CWETOP25ID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"YearTop25" INTEGER NOT NULL,
	"Rank" INTEGER NOT NULL,
	"Score" REAL NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DATACLASSIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATACLASSIFICATION"(
	"DataClassificationID" INTEGER NOT NULL,
	"InformationTypeID" INTEGER NULL
)

;
/****** Object:  Table "DATADICTIONARY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATADICTIONARY"(
	"DataDictionaryID" INTEGER NOT NULL,
	"DictionaryID" INTEGER NULL
)

;
/****** Object:  Table "DATAEXFILTRATIONPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATAEXFILTRATIONPROPERTIES"(
	"DataExfiltrationPropertiesID" INTEGER NOT NULL,
	"DataExfiltrationPropertiesName" TEXT NULL,
	"DataExfiltrationPropertiesDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DATAEXFILTRATIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATAEXFILTRATIONSTRATEGICOBJECTIVE"(
	"DataExfiltrationStrategicObjectiveID" INTEGER NOT NULL,
	"DataExfiltrationStrategicObjectiveName" TEXT NULL,
	"DataExfiltrationStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DATAEXFILTRATIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATAEXFILTRATIONTACTICALOBJECTIVE"(
	"DataExfiltrationTacticalObjectiveID" INTEGER NOT NULL,
	"DataExfiltrationTacticalObjectiveName" TEXT NULL,
	"DataExfiltrationTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DATAFEED"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATAFEED"(
	"DataFeedID" INTEGER NOT NULL,
	"FeedID" INTEGER NULL
)

;
/****** Object:  Table "DATAFORMAT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATAFORMAT"(
	"DataFormatID" INTEGER NOT NULL,
	"DataFormatName" TEXT NULL,
	"DataFormatDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "DATAMODEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATAMODEL"(
	"DataModelID" INTEGER NOT NULL,
	"ModelID" INTEGER NULL
)

;
/****** Object:  Table "DATASEGMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATASEGMENT"(
	"DataSegmentID" INTEGER NOT NULL
)

;
/****** Object:  Table "DATASIZEUNIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATASIZEUNIT"(
	"DataSizeUnitID" INTEGER NOT NULL,
	"DataSizeName" TEXT NOT NULL,
	"DataSizeDescription" TEXT NULL,
	"lang" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "DATATHEFTPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATATHEFTPROPERTIES"(
	"DataTheftPropertiesID" INTEGER NOT NULL,
	"DataTheftPropertiesName" TEXT NULL,
	"DataTheftPropertiesDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "DATATHEFTSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATATHEFTSTRATEGICOBJECTIVE"(
	"DataTheftStrategicObjectiveID" INTEGER NOT NULL,
	"DataTheftStrategicObjectiveName" TEXT NULL,
	"DataTheftStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DATATHEFTTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATATHEFTTACTICALOBJECTIVE"(
	"DataTheftTacticalObjectiveID" INTEGER NOT NULL,
	"DataTheftTacticalObjectiveName" TEXT NULL,
	"DataTheftTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DATATRANSFER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATATRANSFER"(
	"DataTransferID" INTEGER NOT NULL
)

;
/****** Object:  Table "DATATRANSFORMATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATATRANSFORMATION"(
	"DataTransformationID" INTEGER NOT NULL,
	"TransformationID" INTEGER NULL
)

;
/****** Object:  Table "DATATYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATATYPE"(
	"DataTypeID" INTEGER NOT NULL,
	"DataTypeName" TEXT NOT NULL,
	"DataTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DATETIMEFORMAT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DATETIMEFORMAT"(
	"DateTimeFormatID" INTEGER NOT NULL,
	"DateTimeFormatValue" TEXT NOT NULL,
	"DataType" TEXT NOT NULL,
	"DateTimeFormatDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "DEBUGGINGACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEBUGGINGACTIONNAME"(
	"DebuggingActionNameID" INTEGER NOT NULL,
	"DebuggingActionNameName" TEXT NOT NULL,
	"DebuggingActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DEFENSETOOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEFENSETOOL"(
	"DefenseToolID" INTEGER NOT NULL,
	"DefenseToolGUID" TEXT NULL,
	"ToolID" INTEGER NULL,
	"DefenseToolName" TEXT NULL,
	"DefenseToolDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ReliabilityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "DEFENSETOOLTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEFENSETOOLTYPE"(
	"DefenseToolTypeID" INTEGER NOT NULL,
	"DefenseToolTypeName" TEXT NOT NULL,
	"DefenseToolTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "DEMONSTRATIVEEXAMPLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEMONSTRATIVEEXAMPLE"(
	"DemonstrativeExampleID" INTEGER NOT NULL,
	"DemonstrativeExampleGUID" TEXT NULL,
	"DemonstrativeExampleVocabularyID" TEXT NULL,
	"DemonstrativeExampleIntroText" TEXT NULL,
	"DemonstrativeExampleBody" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"LanguageID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DEMONSTRATIVEEXAMPLECODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEMONSTRATIVEEXAMPLECODE"(
	"DemonstrativeExampleCodeID" INTEGER NOT NULL,
	"DemonstrativeExampleID" INTEGER NOT NULL,
	"CodeID" INTEGER NOT NULL,
	"Block_Nature" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "DEMONSTRATIVEEXAMPLEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEMONSTRATIVEEXAMPLEREFERENCE"(
	"DemonstrativeExampleReferenceID" INTEGER NOT NULL,
	"DemonstrativeExampleID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DEMONSTRATIVEEXAMPLEVULNERABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEMONSTRATIVEEXAMPLEVULNERABILITY"(
	"DemonstrativeExampleVulnerabilityID" INTEGER NOT NULL,
	"DemonstrativeExampleID" INTEGER NULL,
	"VulnerabilityID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "DESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DESCRIPTION"(
	"DescriptionID" INTEGER NOT NULL,
	"DescriptionGUID" TEXT NULL,
	"DescriptionText" TEXT NULL,
	"LocaleID" INTEGER NULL,
	"VersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DESCRIPTIONCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DESCRIPTIONCHANGERECORD"(
	"DescriptionChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "DESCRIPTIONREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DESCRIPTIONREFERENCE"(
	"DescriptionReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "DESCRIPTIONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DESCRIPTIONTAG"(
	"DescriptionTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "DESTRUCTIONPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DESTRUCTIONPROPERTIES"(
	"DestructionPropertiesID" INTEGER NOT NULL,
	"DestructionPropertiesName" TEXT NULL,
	"DestructionPropertiesDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DESTRUCTIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DESTRUCTIONSTRATEGICOBJECTIVE"(
	"DestructionStrategicObjectiveID" INTEGER NOT NULL,
	"DestructionStrategicObjectiveName" TEXT NULL,
	"DestructionStrategicObjectiveDestruction" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DESTRUCTIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DESTRUCTIONTACTICALOBJECTIVE"(
	"DestructionTacticalObjectiveID" INTEGER NOT NULL,
	"DestructionTacticalObjectiveName" TEXT NULL,
	"DestructionTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "DETECTABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DETECTABILITY"(
	"DetectabilityID" INTEGER NOT NULL,
	"DetectabilityName" TEXT NOT NULL,
	"DetectabilityDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DETECTIONMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DETECTIONMETHOD"(
	"DetectionMethodID" INTEGER NOT NULL,
	"DetectionMethodGUID" TEXT NULL,
	"MethodID" INTEGER NULL,
	"DetectionMethodVocabularyID" TEXT NULL,
	"DetectionMethodName" TEXT NOT NULL,
	"DetectionMethodDescription" TEXT NULL,
	"DetectionMethodEffectiveness" TEXT NULL,
	"DetectionMethodEffectivenessNotes" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DEVICE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEVICE"(
	"DeviceID" INTEGER NOT NULL,
	"DeviceGUID" TEXT NULL,
	"Device_Type" TEXT NOT NULL,
	"Manufacturer" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"Model" TEXT NULL,
	"Firmware_Version" TEXT NULL,
	"CPEID" INTEGER NULL,
	"CPEName" TEXT NULL,
	"Serial_Number" TEXT NULL,
	"Description" TEXT NULL,
	"ClockSpeedFrequency" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DEVICEBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEVICEBLACKLIST"(
	"DeviceBlacklistID" INTEGER NOT NULL,
	"DeviceID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"CreatedDate" INTEGER NULL,
	"ValidFromDate" INTEGER NULL,
	"ValidUntilDate" INTEGER NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "DEVICECOMPONENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEVICECOMPONENT"(
	"DeviceComponentID" INTEGER NOT NULL,
	"DeviceComponentGUID" TEXT NULL
)

;
/****** Object:  Table "DEVICEDRIVERACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEVICEDRIVERACTIONNAME"(
	"DeviceDriverActionNameID" INTEGER NOT NULL,
	"DeviceDriverActionNameName" TEXT NOT NULL,
	"DeviceDriverActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DEVICETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEVICETYPE"(
	"DeviceTypeID" INTEGER NOT NULL,
	"DeviceTypeGUID" TEXT NULL,
	"DeviceTypeName" TEXT NULL,
	"DeviceTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DEVICEWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DEVICEWHITELIST"(
	"DeviceWhitelistID" INTEGER NOT NULL,
	"DeviceID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "DICTIONARY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DICTIONARY"(
	"DictionaryID" INTEGER NOT NULL
)

;
/****** Object:  Table "DIGITALSIGNATUREINFO"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DIGITALSIGNATUREINFO"(
	"DigitalSignatureInfoID" INTEGER NOT NULL
)

;
/****** Object:  Table "DIGITALSIGNATURES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DIGITALSIGNATURES"(
	"DigitalSignaturesID" INTEGER NOT NULL
)

;
/****** Object:  Table "DIRECTORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DIRECTORY"(
	"DirectoryID" INTEGER NOT NULL,
	"DirectoryGUID" TEXT NULL,
	"DirectoryPathname" TEXT NULL,
	"DirectoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DIRECTORYACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DIRECTORYACTIONNAME"(
	"DirectoryActionNameID" INTEGER NOT NULL,
	"DirectoryActionNameName" TEXT NOT NULL,
	"DirectoryActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DIRECTORYLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DIRECTORYLIST"(
	"DirectoryListID" INTEGER NOT NULL,
	"DirectoryListGUID" TEXT NULL
)

;
/****** Object:  Table "DISCOVERYMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DISCOVERYMETHOD"(
	"DiscoveryMethodID" INTEGER NOT NULL,
	"DiscoveryMethodGUID" TEXT NULL,
	"DiscoveryMethodName" TEXT NULL,
	"MeasureSourceID" INTEGER NULL,
	"DiscoveryMethodDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "DISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DISK"(
	"DiskID" INTEGER NOT NULL
)

;
/****** Object:  Table "DISKACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DISKACTIONNAME"(
	"DiskActionNameID" INTEGER NOT NULL,
	"DiskActionNameName" TEXT NULL,
	"DiskActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DISKPARTITION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DISKPARTITION"(
	"DiskPartitionID" INTEGER NOT NULL
)

;
/****** Object:  Table "DNSACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DNSACTIONNAME"(
	"DNSActionNameID" INTEGER NOT NULL,
	"DNSActionNameName" TEXT NOT NULL,
	"DNSActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DNSCACHE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DNSCACHE"(
	"DNSCacheID" INTEGER NOT NULL
)

;
/****** Object:  Table "DNSQUERY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DNSQUERY"(
	"DNSQueryID" INTEGER NOT NULL,
	"DNDQueryGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DNSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DNSRECORD"(
	"DNSRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "DOCUMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOCUMENT"(
	"DocumentID" INTEGER NOT NULL,
	"DocumentGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"DocumentName" TEXT NULL,
	"DocumentDescription" TEXT NULL,
	"DocumentURL" TEXT NULL,
	"Category" TEXT NULL,
	"Author" TEXT NULL,
	"Classification" TEXT NULL,   -- data-sensitivity label: Public / Internal / Confidential / Restricted
	"TLP" TEXT NULL               -- Traffic Light Protocol 2.0 sharing marker (TLP:CLEAR…TLP:RED)
)

;
/****** Object:  Table "DOCUMENTCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOCUMENTCATEGORY"(
	"DocumentCategoryID" INTEGER NOT NULL,
	"DocumentID" INTEGER NULL,
	"CategoryID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DOCUMENTCLASSIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOCUMENTCLASSIFICATION"(
	"DocumentClassificationID" INTEGER NOT NULL,
	"DocumentID" INTEGER NOT NULL,
	"DocumentGUID" TEXT NULL,
	"ClassificationID" INTEGER NOT NULL,
	"ClassificationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DOCUMENTTITLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOCUMENTTITLE"(
	"DocumentTitleID" INTEGER NOT NULL,
	"DocumentID" INTEGER NOT NULL,
	"DocumentGUID" TEXT NULL,
	"TitleID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DOCUMENTVERSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOCUMENTVERSION"(
	"DocumentVersionID" INTEGER NOT NULL,
	"DocumentID" INTEGER NOT NULL,
	"DocumentGUID" TEXT NULL,
	"VersionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DOCXMLDOCUMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOCXMLDOCUMENT"(
	"DocXMLDocumentID" INTEGER NOT NULL,
	"DocumentID" INTEGER NULL
)

;
/****** Object:  Table "DOMAIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAIN"(
	"DomainID" INTEGER NOT NULL,
	"DomainGUID" TEXT NULL,
	"DomainName" TEXT NOT NULL,
	"DomainDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DOMAINBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINBLACKLIST"(
	"DomainBlacklistID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DOMAINEMAILADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINEMAILADDRESS"(
	"DomainEmailAddressID" INTEGER NOT NULL,
	"DomainID" INTEGER NOT NULL,
	"EmailAddressID" INTEGER NOT NULL,
	"emailaddress" TEXT NOT NULL
)

;
/****** Object:  Table "DOMAINNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINNAME"(
	"DomainNameID" INTEGER NOT NULL,
	"DomainNameValue" TEXT NULL,
	"DomainNameTypeID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DOMAINNAMEBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINNAMEBLACKLIST"(
	"DomainNameBlacklistID" INTEGER NOT NULL
)

;
/****** Object:  Table "DOMAINNAMECHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINNAMECHANGERECORD"(
	"DomainNameChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "DOMAINNAMEREPUTATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINNAMEREPUTATION"(
	"DomainNameReputationID" INTEGER NOT NULL,
	"DomainNameID" INTEGER NULL,
	"ReputationID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DOMAINNAMETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINNAMETYPE"(
	"DomainNameTypeID" INTEGER NOT NULL,
	"DomainNameTypeValue" TEXT NULL,
	"DomainNameTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"VocabularyGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DOMAINORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINORGANISATION"(
	"DomainOrganisationID" INTEGER NOT NULL,
	"DomainID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"DomainOrganisationDescription" TEXT NULL,
	"RelationshipTypeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "DOMAINPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINPERSON"(
	"DomainPersonID" INTEGER NOT NULL,
	"DomainID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL
)

;
/****** Object:  Table "DOMAINTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINTYPE"(
	"DomainTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "DOMAINTYPEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINTYPEENUM"(
	"DomainTypeEnumID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "DOMAINWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOMAINWHITELIST"(
	"DomainWhitelistID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "DOWNTIME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DOWNTIME"(
	"DowntimeID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"DownFromDate" TEXT NULL,
	"DownToDate" TEXT NOT NULL,
	"DowntimeDuration" INTEGER NULL,
	"DowntimePlanned" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" TEXT NULL
)

;
/****** Object:  Table "DPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "DPE"(
	"DPEID" INTEGER NOT NULL,
	"CPEID" TEXT NULL,
	"CredentialID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"PortID" INTEGER NULL,
	"ProtocolID" INTEGER NULL
)

;
/****** Object:  Table "EDGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EDGE"(
	"EdgeID" INTEGER NOT NULL
)

;
/****** Object:  Table "EFFECTIVENESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EFFECTIVENESS"(
	"EffectivenessID" INTEGER NOT NULL,
	"EffectivenessGUID" TEXT NULL,
	"EffectivenessName" TEXT NOT NULL,
	"EffectivenessDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EFFECTTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EFFECTTYPE"(
	"EffectTypeID" INTEGER NOT NULL,
	"EffectTypeName" TEXT NOT NULL,
	"EffectTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "EMAIL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAIL"(
	"EmailID" INTEGER NOT NULL,
	"emailaddress" TEXT NOT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EMAILADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILADDRESS"(
	"EmailAddressID" INTEGER NOT NULL,
	"EmailAddressGUID" TEXT NULL,
	"EmailID" INTEGER NULL,
	"emailaddress" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL
)

;
/****** Object:  Table "EMAILFORORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILFORORGANISATION"(
	"emailaddress" TEXT NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "EMAILFORPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILFORPERSON"(
	"emailaddress" TEXT NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EMAILHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILHEADER"(
	"EmailHeaderID" INTEGER NOT NULL,
	"EmailHeaderGUID" TEXT NULL,
	"HeaderID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"Received_Lines" INTEGER NULL,
	"EmailTo" INTEGER NULL,
	"EmailCC" INTEGER NULL,
	"EmailBCC" INTEGER NULL,
	"EmailFrom" INTEGER NULL,
	"EmailSubject" TEXT NULL,
	"In_Reply_To" TEXT NULL,
	"DateSent" TEXT NULL,
	"Message_ID" TEXT NULL,
	"Sender" INTEGER NULL,
	"Reply_To" INTEGER NULL,
	"Errors_To" TEXT NULL,
	"Boundary" TEXT NULL,
	"Content_Type" TEXT NULL,
	"MIMEID" INTEGER NULL,
	"MIME_Version" TEXT NULL,
	"Precedence" TEXT NULL,
	"User_Agent" TEXT NULL,
	"UserAgentID" INTEGER NULL,
	"UserAgentGUID" TEXT NULL,
	"X_Mailer" TEXT NULL,
	"X_Originating_IP" INTEGER NULL,
	"X_Priority" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL
)

;
/****** Object:  Table "EMAILHEADERTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILHEADERTAG"(
	"EmailHeaderTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "EMAILMESSAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILMESSAGE"(
	"EmailMessageID" INTEGER NOT NULL,
	"EmailMessageGUID" TEXT NULL,
	"MessageID" INTEGER NULL,
	"EmailMessageIsEncrypted" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"Email_Server" TEXT NULL,
	"CPEID" TEXT NULL,
	"AssetEmailServerID" INTEGER NULL,
	"AssetEmailServerGUID" TEXT NULL,
	"AssetSourceID" INTEGER NULL,
	"AssetSourceGUID" TEXT NULL,
	"AssetDestinationID" INTEGER NULL,
	"AssetDestinationGUID" TEXT NULL,
	"Raw_Body" TEXT NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"Raw_Header" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "EMAILMESSAGEATTACHMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILMESSAGEATTACHMENT"(
	"EmailMessageAttachmentID" INTEGER NOT NULL,
	"EmailMessageID" INTEGER NOT NULL,
	"EmailMessageGUID" TEXT NULL,
	"AttachmentID" INTEGER NOT NULL,
	"AttachmentGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EMAILMESSAGECLASSIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILMESSAGECLASSIFICATION"(
	"EmailMessageClassificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "EMAILMESSAGELINK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILMESSAGELINK"(
	"EmailMessageLinkID" INTEGER NOT NULL,
	"EmailMessageID" INTEGER NOT NULL,
	"LinkID" INTEGER NOT NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EMAILMESSAGERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILMESSAGERESTRICTION"(
	"EmailMessageRestrictionID" INTEGER NOT NULL,
	"EmailMessageID" INTEGER NOT NULL,
	"RestrictionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EMAILMESSAGETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILMESSAGETAG"(
	"EmailMessageTagID" INTEGER NOT NULL,
	"EmailMessageID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EMAILRECEIVEDLINELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILRECEIVEDLINELIST"(
	"EmailReceivedLineListID" INTEGER NOT NULL
)

;
/****** Object:  Table "EMAILRECIPIENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILRECIPIENT"(
	"EmailRecipientID" INTEGER NOT NULL,
	"EmailAddressID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EMAILRECIPIENTS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILRECIPIENTS"(
	"EmailRecipientsID" INTEGER NOT NULL,
	"EmailRecipientsGUID" TEXT NULL,
	"GroupID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EMAILRECIPIENTSLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EMAILRECIPIENTSLIST"(
	"EmailRecipientsListID" INTEGER NOT NULL,
	"EmailRecipientsID" INTEGER NOT NULL,
	"EmailRecipientsGUID" TEXT NULL,
	"EmailRecipientID" INTEGER NOT NULL,
	"EmailRecipientGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ENCODING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENCODING"(
	"EncodingID" INTEGER NOT NULL,
	"algorithm" TEXT NOT NULL,
	"EncodingAlgorithmID" INTEGER NULL,
	"EncodingDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ENCODINGALGORITHM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENCODINGALGORITHM"(
	"EncodingAlgorithmID" INTEGER NOT NULL,
	"AlgorithmID" INTEGER NULL
)

;
/****** Object:  Table "ENCRYPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENCRYPTION"(
	"EncryptionID" INTEGER NOT NULL,
	"encryption_mechanism" TEXT NOT NULL,
	"EncryptionMechanismID" INTEGER NULL,
	"encryption_mechanism_ref" TEXT NULL,
	"EncryptionDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "ENCRYPTIONKEY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENCRYPTIONKEY"(
	"EncryptionKeyID" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ENCRYPTIONMECHANISM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENCRYPTIONMECHANISM"(
	"EncryptionMechanismID" INTEGER NOT NULL,
	"MechanismID" INTEGER NULL,
	"EncryptionMechanismName" TEXT NULL,
	"EncryptionMechanismDescription" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ENCRYPTIONREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENCRYPTIONREFERENCE"(
	"EncryptionReferenceID" INTEGER NOT NULL,
	"EncryptionID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "ENDFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENDFUNCTION"(
	"EndFunctionID" INTEGER NOT NULL,
	"EndsWithCharacters" TEXT NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL
)

;
/****** Object:  Table "ENDIANNESSTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENDIANNESSTYPE"(
	"EndiannessTypeID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ENDPOINT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENDPOINT"(
	"EndPointID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"DeviceID" INTEGER NULL,
	"AddressID" INTEGER NULL,
	"ProtocolID" INTEGER NULL,
	"ProtocolName" TEXT NULL,
	"PortID" INTEGER NULL,
	"PortNumber" INTEGER NULL,
	"Service" TEXT NULL,
	"Version" TEXT NULL,
	"CPEName" TEXT NULL,
	"SessionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ENGINE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENGINE"(
	"EngineID" INTEGER NOT NULL,
	"EngineName" TEXT NULL,
	"EngineDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ENTITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENTITY"(
	"EntityID" INTEGER NOT NULL
)

;
/****** Object:  Table "ENTITYDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENTITYDESCRIPTION"(
	"EntityDescriptionID" INTEGER NOT NULL,
	"EntityID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "ENTITYNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENTITYNAME"(
	"EntityNameID" INTEGER NOT NULL,
	"EntityID" INTEGER NOT NULL,
	"NameID" INTEGER NOT NULL
)

;
/****** Object:  Table "ENTITYRESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENTITYRESTRICTION"(
	"EntityRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "ENTITYTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENTITYTYPE"(
	"EntityTypeID" INTEGER NOT NULL,
	"EntityID" INTEGER NOT NULL,
	"TypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "ENTRYPOINT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENTRYPOINT"(
	"EntryPointID" INTEGER NOT NULL
)

;
/****** Object:  Table "ENTRYVARIABLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENTRYVARIABLE"(
	"EntryVariableID" INTEGER NOT NULL,
	"VariableID" INTEGER NULL
)

;
/****** Object:  Table "ENUMERATIONVERSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENUMERATIONVERSION"(
	"EnumerationVersionID" INTEGER NOT NULL,
	"EnumerationName" TEXT NULL,
	"VersionID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ENVIRONMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ENVIRONMENT"(
	"EnvironmentID" INTEGER NOT NULL,
	"CapecEnvironmentID" TEXT NULL,
	"EnvironmentTitle" TEXT NOT NULL,
	"EnvironmentDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ESCAPEREGEXFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ESCAPEREGEXFUNCTION"(
	"EscapeRegexFunctionID" INTEGER NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL
)

;
/****** Object:  Table "EVALUATIONMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVALUATIONMETHOD"(
	"EvaluationMethodID" INTEGER NOT NULL,
	"MethodID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ReliabilityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EVENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENT"(
	"EventID" INTEGER NOT NULL,
	"EventGUID" TEXT NULL,
	"EventName" TEXT NULL,
	"EventTypeID" INTEGER NULL,
	"start_datetime" TEXT NULL,
	"stop_datetime" TEXT NULL,
	"AnomalyEvent" INTEGER NULL,
	"AnomalyDescription" TEXT NULL,
	"AuditRecordEvent" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EVENTCOLLECTIONMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTCOLLECTIONMETHOD"(
	"EventCollectionMethodID" INTEGER NOT NULL,
	"EventID" INTEGER NOT NULL,
	"EventGUID" TEXT NULL,
	"CollectionMethodID" INTEGER NOT NULL,
	"CollectionMethodGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"AssetID" INTEGER NULL,
	"DeviceID" INTEGER NULL,
	"ProductID" INTEGER NULL,
	"CPEID" INTEGER NULL,
	"CPEName" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EVENTCOMMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTCOMMENT"(
	"EventCommentID" INTEGER NOT NULL,
	"Comment" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "EVENTCOMMENTFOREVENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTCOMMENTFOREVENT"(
	"EventEventCommentID" INTEGER NOT NULL,
	"EventID" INTEGER NOT NULL,
	"EventCommentID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EVENTENDPOINT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTENDPOINT"(
	"EndPointEventID" INTEGER NOT NULL,
	"EventID" INTEGER NOT NULL,
	"EndPointID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EVENTFILTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTFILTER"(
	"EventFilterID" INTEGER NOT NULL,
	"EventFilterContent" TEXT NULL,
	"EventFilterDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EVENTFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTFORASSET"(
	"AssetEventID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"relationshiptype" TEXT NULL,
	"relationshipscope" TEXT NULL,
	"EventID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "EVENTFOREVENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTFOREVENT"(
	"EventForEventID" INTEGER NOT NULL,
	"EventRefID" INTEGER NOT NULL,
	"relationshiptype" TEXT NULL,
	"relationshipscope" TEXT NULL,
	"EventSubjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EVENTFORINCIDENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTFORINCIDENT"(
	"IncidentEventID" INTEGER NOT NULL,
	"EventID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EVENTPROPERTY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTPROPERTY"(
	"EventPropertyID" INTEGER NOT NULL,
	"EventPropertyGUID" TEXT NULL,
	"EventPropertyIDREF" TEXT NULL,
	"EventPropertyName" TEXT NULL,
	"EventPropertyDescription" TEXT NULL,
	"appears_random" INTEGER NULL,
	"datatype" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "EVENTPROPERTYADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTPROPERTYADDRESS"(
	"EventPropertyAddressID" INTEGER NOT NULL,
	"EventPropertyID" INTEGER NOT NULL,
	"AddressID" INTEGER NOT NULL
)

;
/****** Object:  Table "EVENTPROPERTYFOREVENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTPROPERTYFOREVENT"(
	"EventEventPropertyID" INTEGER NOT NULL,
	"EventID" INTEGER NOT NULL,
	"EventPropertyID" INTEGER NOT NULL,
	"EventPropertyValue" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EVENTSIGNATURE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTSIGNATURE"(
	"EventSignatureID" INTEGER NOT NULL,
	"EventSignatureGUID" TEXT NULL,
	"EventID" INTEGER NOT NULL,
	"EventGUID" TEXT NULL,
	"SignatureID" INTEGER NOT NULL,
	"SignatureGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"total_packets_collected" INTEGER NULL,
	"total_bytes_collected" INTEGER NULL,
	"data_flow_direction" TEXT NULL,
	"connection_start_datetime" TEXT NULL,
	"connection_end_datetime" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EVENTSUPPRESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTSUPPRESSION"(
	"EventSuppressionID" INTEGER NOT NULL,
	"EventSuppressionContent" TEXT NULL,
	"EventSuppressionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EVENTTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVENTTYPE"(
	"EventTypeID" INTEGER NOT NULL,
	"EventTypeName" TEXT NOT NULL,
	"EventTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EVIDENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVIDENCE"(
	"EvidenceID" INTEGER NOT NULL,
	"EvidenceGUID" TEXT NULL,
	"EvidenceName" TEXT NULL,
	"EvidenceDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"SourceID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ReliabilityID" INTEGER NULL
)

;
/****** Object:  Table "EVIDENCEACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVIDENCEACCESSRECORD"(
	"EvidenceAccessRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "EVIDENCEACL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVIDENCEACL"(
	"EvidenceACLID" INTEGER NOT NULL
)

;
/****** Object:  Table "EVIDENCECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVIDENCECATEGORY"(
	"EvidenceCategoryID" INTEGER NOT NULL,
	"EvidenceCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"EvidenceCategoryName" TEXT NULL,
	"EvidenceCategoryDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ReliabilityID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "EVIDENCERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EVIDENCERESTRICTION"(
	"EvidenceRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "EXCELFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXCELFILE"(
	"ExcelFileID" INTEGER NOT NULL,
	"FileID" INTEGER NULL
)

;
/****** Object:  Table "EXIFTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXIFTAG"(
	"EXIFTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "EXISTENCEENUMERATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXISTENCEENUMERATION"(
	"ExistenceEnumerationID" INTEGER NOT NULL,
	"ExistenceValue" TEXT NOT NULL,
	"ExistenceDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EXPLOIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOIT"(
	"ExploitID" INTEGER NOT NULL,
	"ExploitGUID" TEXT NULL,
	"ExploitReferential" TEXT NULL,
	"ExploitRefID" TEXT NULL,
	"SourceID" INTEGER NULL,
	"SourceGUID" TEXT NULL,
	"ExploitName" TEXT NULL,
	"ExploitLocation" TEXT NULL,
	TEXT TEXT NULL,
	"Verification" INTEGER NULL,
	"Platform" TEXT NULL,
	"Author" TEXT NULL,
	"AuthorID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"RPORT" INTEGER NULL,
	"ExploitDescription" TEXT NULL,
	"ExploitType" TEXT NULL,
	"CodeID" INTEGER NULL,
	"ExploitCode" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ReliabilityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"LastCheckDate" TEXT NULL
)

;
/****** Object:  Table "EXPLOITABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITABILITY"(
	"ExploitabilityID" INTEGER NOT NULL,
	"ExploitabilityLevel" TEXT NOT NULL,
	"ExploitabilityDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EXPLOITACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITACCESSRECORD"(
	"ExploitAccessRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "EXPLOITATIONFACTOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITATIONFACTOR"(
	"ExploitationFactorID" INTEGER NOT NULL,
	"ExploitationFactorGUID" TEXT NULL,
	"ExploitationFactorName" TEXT NULL,
	"ExploitationFactorDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "EXPLOITAUTHOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITAUTHOR"(
	"ExploitAuthorID" INTEGER NOT NULL,
	"ExploitID" INTEGER NOT NULL,
	"ExploitGUID" TEXT NULL,
	"AuthorID" INTEGER NOT NULL,
	"AuthorGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITCATEGORY"(
	"ExploitCategoryID" INTEGER NOT NULL,
	"CategoryID" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITCHANGERECORD"(
	"ExploitChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "EXPLOITDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITDESCRIPTION"(
	"ExploitDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "EXPLOITFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITFILE"(
	"ExploitFileID" INTEGER NOT NULL
)

;
/****** Object:  Table "EXPLOITFORCPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITFORCPE"(
	"CPEExploitID" INTEGER NOT NULL,
	"CPEExploitGUID" TEXT NULL,
	"CPEID" INTEGER NULL,
	"CPEName" TEXT NULL,
	"ExploitID" INTEGER NOT NULL,
	"ExploitGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ExploitCPEName" TEXT NULL,
	"ExploitCPEDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITFORFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITFORFUNCTION"(
	"ExploitFunctionID" INTEGER NOT NULL,
	"ExploitFunctionGUID" TEXT NULL,
	"ExploitID" INTEGER NOT NULL,
	"ExploitGUID" TEXT NULL,
	"ExploitFunctionRelationship" TEXT NULL,
	"FunctionID" INTEGER NOT NULL,
	"FunctionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITFORREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITFORREFERENCE"(
	"ExploitReferenceID" INTEGER NOT NULL,
	"ExploitReferenceGUID" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"ExploitID" INTEGER NOT NULL,
	"ExploitGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITFORTECHNOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITFORTECHNOLOGY"(
	"ExploitTechnologyID" INTEGER NOT NULL,
	"TechnologyID" INTEGER NULL,
	"ExploitID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITFORTHREATACTORTTP"(
	"ThreatActorTTPExploitID" INTEGER NOT NULL,
	"ExploitID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "EXPLOITFORURI"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITFORURI"(
	"ExploitURIID" INTEGER NOT NULL,
	"URIObjectID" INTEGER NULL,
	"ExploitID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITFORVULNERABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITFORVULNERABILITY"(
	"VulnerabilityExploitID" INTEGER NOT NULL,
	"VulnerabilityExploitGUID" TEXT NULL,
	"VulnerabilityExploitDescription" TEXT NULL,
	"ExploitID" INTEGER NOT NULL,
	"ExploitGUID" TEXT NULL,
	"VulnerabilityID" INTEGER NOT NULL,
	"VulnerabilityGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"RepositoryID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITLANGUAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITLANGUAGE"(
	"ExploitLanguageID" INTEGER NOT NULL,
	"ExploitID" INTEGER NULL,
	"ExploitGUID" TEXT NULL,
	"LanguageID" INTEGER NULL,
	"LanguageGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITLIKELIHOOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITLIKELIHOOD"(
	"ExploitLikelihoodID" INTEGER NOT NULL,
	"Likelihood" TEXT NOT NULL,
	"LikelihoodDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "EXPLOITLIKELIHOODFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITLIKELIHOODFORATTACKPATTERN"(
	"AttackPatternExploitLikelihoodID" INTEGER NOT NULL,
	"ExploitLikelihoodID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"Explanation" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITLIKELIHOODFORCWE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITLIKELIHOODFORCWE"(
	"ExploitLikelihoodForCWEID" INTEGER NOT NULL,
	"CWEID" TEXT NOT NULL,
	"ExploitLikelihoodID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"RepositoryID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITOSINSTRUCTIONMEMORYADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITOSINSTRUCTIONMEMORYADDRESS"(
	"ExploitOSInstructionMemoryAddressID" INTEGER NOT NULL,
	"ExploitID" INTEGER NOT NULL,
	"OSInstructionMemoryAddressID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITPARAMETER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITPARAMETER"(
	"ExploitParameterID" INTEGER NOT NULL,
	"ExploitParameterName" TEXT NOT NULL,
	"DefaultValue" TEXT NULL,
	"ExploitParameterDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "EXPLOITPARAMETERFOREXPLOIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITPARAMETERFOREXPLOIT"(
	"ExploitParametersID" INTEGER NOT NULL,
	"ExploitID" INTEGER NOT NULL,
	"ExploitParameterID" INTEGER NOT NULL,
	"OrderRank" INTEGER NULL,
	"DefaultValue" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "EXPLOITPLATFORM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITPLATFORM"(
	"ExploitPlatformID" INTEGER NOT NULL,
	"ExploitID" INTEGER NULL,
	"PlatformID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EXPLOITRESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITRESTRICTION"(
	"ExploitRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "EXPLOITTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPLOITTAG"(
	"ExploitTagID" INTEGER NOT NULL,
	"ExploitID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "EXPOSURELEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXPOSURELEVEL"(
	"ExposureLevelID" INTEGER NOT NULL
)

;
/****** Object:  Table "EXTRACTEDFEATURES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "EXTRACTEDFEATURES"(
	"ExtractedFeaturesID" INTEGER NOT NULL
)

;
/****** Object:  Table "FACILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FACILITY"(
	"FacilityID" INTEGER NOT NULL
)

;
/****** Object:  Table "FACILITYPHYSICALLOCATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FACILITYPHYSICALLOCATION"(
	"FacilityPhysicalLocationID" INTEGER NOT NULL
)

;
/****** Object:  Table "FACTORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FACTORY"(
	"FactoryID" INTEGER NOT NULL,
	"ManufacturID" INTEGER NULL
)

;
/****** Object:  Table "FACTORYASSURANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FACTORYASSURANCE"(
	"FactoryAssuranceID" INTEGER NOT NULL
)

;
/****** Object:  Table "FACTORYCOMPLIANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FACTORYCOMPLIANCE"(
	"FactoryComplianceID" INTEGER NOT NULL
)

;
/****** Object:  Table "FACTORYPOLICY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FACTORYPOLICY"(
	"FactoryPolicyID" INTEGER NOT NULL
)

;
/****** Object:  Table "FAX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FAX"(
	"FaxID" INTEGER NOT NULL,
	"TelephoneID" INTEGER NULL
)

;
/****** Object:  Table "FEED"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FEED"(
	"FeedID" INTEGER NOT NULL,
	"RepositoryID" INTEGER NULL,
	"ReferenceID" INTEGER NULL
)

;
/****** Object:  Table "FIELD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIELD"(
	"FieldID" INTEGER NOT NULL
)

;
/****** Object:  Table "FILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILE"(
	"FileID" INTEGER NOT NULL,
	"FileGUID" TEXT NULL,
	"FileName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FILEACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEACTIONNAME"(
	"FileActionNameID" INTEGER NOT NULL,
	"FileActionNameName" TEXT NOT NULL,
	"FileActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "FILECHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILECHANGERECORD"(
	"FileChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "FILECLASSIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILECLASSIFICATION"(
	"FileClassificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "FILEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEDESCRIPTION"(
	"FileDescriptionID" INTEGER NOT NULL,
	"FileID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FILEENCRYPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEENCRYPTION"(
	"FileEncryptionID" INTEGER NOT NULL,
	"FileID" INTEGER NOT NULL,
	"EncryptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FILEEXTENSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEEXTENSION"(
	"FileExtensionID" INTEGER NOT NULL,
	"FileExtensionGUID" TEXT NULL,
	"FileExtensionName" TEXT NULL,
	"FileExtensionDescription" TEXT NULL,
	"FileExtensionValue" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FILEEXTENSIONBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEEXTENSIONBLACKLIST"(
	"FileExtensionBlacklistID" INTEGER NOT NULL
)

;
/****** Object:  Table "FILEEXTENSIONWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEEXTENSIONWHITELIST"(
	"FileExtensionWhitelistID" INTEGER NOT NULL
)

;
/****** Object:  Table "FILELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILELIST"(
	"FileListID" INTEGER NOT NULL,
	"FileListGUID" TEXT NULL,
	"FileListName" TEXT NULL,
	"FileListDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FILELISTFILES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILELISTFILES"(
	"FileListFileID" INTEGER NOT NULL,
	"FileListID" INTEGER NOT NULL,
	"FileListGUID" TEXT NULL,
	"FileID" INTEGER NOT NULL,
	"FileGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FILEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEREFERENCE"(
	"FileReferenceID" INTEGER NOT NULL,
	"FileReferenceGUID" TEXT NULL,
	"FileID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FILEREPOSITORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEREPOSITORY"(
	"FileRepositoryID" INTEGER NOT NULL,
	"FileID" INTEGER NOT NULL,
	"FileGUID" TEXT NULL,
	"RepositoryID" INTEGER NOT NULL,
	"RepositoryGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "FILERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILERESTRICTION"(
	"FileRestrictionID" INTEGER NOT NULL,
	"FileID" INTEGER NOT NULL,
	"RestrictionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "FILERESTRICTIONCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILERESTRICTIONCHANGERECORD"(
	"FileRestrictionChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "FILETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILETAG"(
	"FileTagID" INTEGER NOT NULL,
	"FileID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FILEVERSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILEVERSION"(
	"FileVersionID" INTEGER NOT NULL
)

;
/****** Object:  Table "FILTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILTER"(
	"FilterID" INTEGER NOT NULL
)

;
/****** Object:  Table "FILTERACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FILTERACTION"(
	"FilterActionID" INTEGER NOT NULL,
	"FilterActionValue" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FINDING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDING"(
	"FindingID" INTEGER NOT NULL,
	"FindingGUID" TEXT NULL,
	"FindingName" TEXT NULL,
	"FindingDescription" TEXT NULL,
	"ImportanceID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"EndPointID" INTEGER NULL,
	"ApplicationID" INTEGER NULL,
	"FindingStatus" TEXT NULL,
	"CriticalityLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ReportedDate" TEXT NULL,
	"FindingDecision" TEXT NULL,
	"MitigationDate" TEXT NULL,
	"RemediationDate" TEXT NULL,
	"FindingResult" TEXT NULL,
	"FindingURL" TEXT NULL,
	"VulnerableParameterType" TEXT NULL,
	"VulnerableParameter" TEXT NULL,
	"VulnerableParameterValue" TEXT NULL,
	"FindingRequest" TEXT NULL,
	"RequestType" TEXT NULL,
	"FindingResponse" TEXT NULL,
	"IsFalsePositive" INTEGER NULL,
	"VulnerabilityID" INTEGER NULL,
	BLOB TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"JobID" INTEGER NULL
)

;
/****** Object:  Table "FINDINGASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGASSET"(
	"FindingAssetID" INTEGER NOT NULL,
	"FindingAssetGUID" TEXT NULL,
	"FindingID" INTEGER NULL,
	"FindingGUID" TEXT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"FindingAssetRelationship" TEXT NULL,
	"FindingAssetDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FINDINGCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGCATEGORY"(
	"FindingCategoryID" INTEGER NOT NULL,
	"FindingCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"FindingCategoryName" TEXT NULL,
	"FindingCategoryDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ImportanceID" INTEGER NULL
)

;
/****** Object:  Table "FINDINGCATEGORYRACIMATRIX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGCATEGORYRACIMATRIX"(
	"FindingCategoryRACIMatrixID" INTEGER NOT NULL
)

;
/****** Object:  Table "FINDINGCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGCHANGERECORD"(
	"FindingChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "FINDINGCODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGCODE"(
	"FindingCodeID" INTEGER NOT NULL,
	"FindingID" INTEGER NOT NULL,
	"CodeID" INTEGER NOT NULL,
	"CodeLineID" INTEGER NULL,
	"FindingCodeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"CriticalityLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FINDINGDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGDESCRIPTION"(
	"FindingDescriptionID" INTEGER NOT NULL,
	"FindingDescriptionGUID" TEXT NULL,
	"FindingID" INTEGER NOT NULL,
	"FindingGUID" TEXT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"DescriptionGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FINDINGEVIDENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGEVIDENCE"(
	"FindingEvidenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "FINDINGHTTPSESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGHTTPSESSION"(
	"FindingHTTPSessionID" INTEGER NOT NULL
)

;
/****** Object:  Table "FINDINGIMPACT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGIMPACT"(
	"FindingImpactID" INTEGER NOT NULL,
	"FindingID" INTEGER NULL,
	"FindingGUID" TEXT NULL,
	"ImpactID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FINDINGMATURITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGMATURITY"(
	"FindingMaturityID" INTEGER NOT NULL,
	"FindingID" INTEGER NULL,
	"FindingGUID" TEXT NULL,
	"SecurityDomainMaturityID" INTEGER NULL,
	"SecurityDomainMaturityGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "FINDINGPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGPERSON"(
	"FindingPersonID" INTEGER NOT NULL,
	"FindingPersonGUID" TEXT NULL,
	"FindingID" INTEGER NULL,
	"FindingGUID" TEXT NULL,
	"FindingPersonRelationship" TEXT NULL,
	"FindingPersonDescription" TEXT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"LastCheckedDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FINDINGRACIMATRIX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGRACIMATRIX"(
	"FindingRACIMatrixID" INTEGER NOT NULL
)

;
/****** Object:  Table "FINDINGRECOMMENDATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGRECOMMENDATION"(
	"FindingRecommendationID" INTEGER NOT NULL,
	"FindingID" INTEGER NOT NULL,
	"RecommendationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"FindingRecommendationName" TEXT NULL,
	"FindingRecommendationDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FINDINGREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGREFERENCE"(
	"FindingReferenceID" INTEGER NOT NULL,
	"FindingID" INTEGER NOT NULL,
	"FindingGUID" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FINDINGSTATUS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGSTATUS"(
	"FindingStatusID" INTEGER NOT NULL,
	"FindingStatusDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "FINDINGTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGTAG"(
	"FindingTagID" INTEGER NOT NULL,
	"FindingID" INTEGER NOT NULL,
	"FindingGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ImportanceID" INTEGER NULL
)

;
/****** Object:  Table "FINDINGVULNERABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FINDINGVULNERABILITY"(
	"FindingVulnerabilityID" INTEGER NOT NULL,
	"FindingID" INTEGER NULL,
	"VulnerabilityID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"FindingVulnerabilityName" TEXT NULL,
	"FindingVulnerabilityDescription" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FIREWALLRULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIREWALLRULE"(
	"FirewallRuleID" INTEGER NOT NULL,
	"FirewallRuleGUID" TEXT NULL,
	"RuleID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ToolGenerationID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ReliabilityID" INTEGER NULL,
	"ReliabilityReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL,
	"ToolDeploymentID" INTEGER NULL
)

;
/****** Object:  Table "FIREWALLRULEADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIREWALLRULEADDRESS"(
	"FirewallRuleAddressID" INTEGER NOT NULL
)

;
/****** Object:  Table "FIREWALLRULECHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIREWALLRULECHANGERECORD"(
	"FirewallRuleChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "FIREWALLRULECHANGEREQUEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIREWALLRULECHANGEREQUEST"(
	"FirewallRuleChangeRequestID" INTEGER NOT NULL
)

;
/****** Object:  Table "FIXACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIXACTION"(
	"FixActionID" INTEGER NOT NULL,
	"FixActionGUID" TEXT NULL,
	"description" TEXT NULL,
	"type" TEXT NULL,
	"source" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"lang" TEXT NULL,
	"id" TEXT NULL,
	"reboot" INTEGER NULL,
	"strategy" TEXT NULL,
	"disruption" TEXT NULL,
	"complexity" TEXT NULL,
	"systemURI" TEXT NULL,
	"platformURI" TEXT NULL,
	"XCCDFContent" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FIXACTIONCOST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIXACTIONCOST"(
	"FixActionCostID" INTEGER NOT NULL,
	"cost_corrective_action" TEXT NOT NULL
)

;
/****** Object:  Table "FIXACTIONFORFIXACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIXACTIONFORFIXACTION"(
	"FixActionRelationshipID" INTEGER NOT NULL,
	"FixActionRefID" INTEGER NOT NULL,
	"relationshiptype" TEXT NULL,
	"FixActionSubjectID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "FIXACTIONFORINCIDENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIXACTIONFORINCIDENT"(
	"FixActionForIncidentID" INTEGER NOT NULL,
	"FixActionID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"FixActionCostID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FIXACTIONFORVULNERABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIXACTIONFORVULNERABILITY"(
	"VulnerabilityFixActionID" INTEGER NOT NULL,
	"FixActionID" INTEGER NOT NULL,
	"FixActionGUID" TEXT NULL,
	"VulnerabilityID" INTEGER NOT NULL,
	"VulnerabilityGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FIXACTIONPATCH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIXACTIONPATCH"(
	"FixActionPatchID" INTEGER NOT NULL,
	"FixActionID" INTEGER NULL,
	"FixActionGUID" TEXT NULL,
	"FixActionPatchRelationship" TEXT NULL,
	"FixActionPatchDescription" TEXT NULL,
	"PatchID" INTEGER NULL,
	"PatchGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FIXSYSTEM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FIXSYSTEM"(
	"FixSystemID" INTEGER NOT NULL,
	"systemURI" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FLAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FLAG"(
	"FlagID" INTEGER NOT NULL,
	"FlagValue" TEXT NOT NULL,
	"FlagDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FRAMEWORK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FRAMEWORK"(
	"FrameworkID" INTEGER NOT NULL,
	"FrameworkName" TEXT NOT NULL,
	"FrameworkVersion" TEXT NULL,
	"FrameworkDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FRAMEWORKFORTECHNICALCONTEXT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FRAMEWORKFORTECHNICALCONTEXT"(
	"TechnicalContextFrameworkID" INTEGER NOT NULL,
	"TechnicalContextFrameworkGUID" TEXT NULL,
	"FrameworkID" INTEGER NOT NULL,
	"TechnicalContextID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FRAMEWORKREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FRAMEWORKREFERENCE"(
	"FrameworkReferenceID" INTEGER NOT NULL,
	"FrameworkReferenceDescription" TEXT NULL,
	"FrameworkID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FRAUDSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FRAUDSTRATEGICOBJECTIVE"(
	"FraudStrategicObjectiveID" INTEGER NOT NULL,
	"FraudStrategicObjectiveName" TEXT NULL,
	"FraudStrategicObjectiveDestruction" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FRAUDTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FRAUDTACTICALOBJECTIVE"(
	"FraudTacticalObjectiveID" INTEGER NOT NULL,
	"FraudTacticalObjectiveName" TEXT NULL,
	"FraudTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "FREQUENCY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FREQUENCY"(
	"FrequencyID" INTEGER NOT NULL,
	"rate" REAL NOT NULL,
	"scale" TEXT NOT NULL,
	"TrendID" INTEGER NULL,
	"TrendName" TEXT NULL,
	"TimeUnitID" INTEGER NULL,
	"units" TEXT NOT NULL
)

;
/****** Object:  Table "FTPACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FTPACTIONNAME"(
	"FTPActionNameID" INTEGER NOT NULL,
	"FTPActionNameName" TEXT NOT NULL,
	"FTPActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "FUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTION"(
	"FunctionID" INTEGER NOT NULL,
	"FunctionName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"KnownVulnerable" INTEGER NULL,
	"deprecated" INTEGER NULL,
	"FunctionVersion" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"FunctionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "FUNCTIONALAREA"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTIONALAREA"(
	"FunctionalAreaID" INTEGER NOT NULL,
	"FunctionalAreaGUID" TEXT NULL,
	"FunctionalAreaName" TEXT NULL,
	"FunctionalAreaDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ImportanceID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "FUNCTIONARGUMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTIONARGUMENT"(
	"FunctionArgumentID" INTEGER NOT NULL,
	"FunctionID" INTEGER NULL,
	"FunctionArgumentName" TEXT NOT NULL,
	"FunctionArgumentDescription" TEXT NULL,
	"FunctionArgumentType" TEXT NULL
)

;
/****** Object:  Table "FUNCTIONCHARACTERDELIMITER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTIONCHARACTERDELIMITER"(
	"FunctionCharacterDelimiterID" INTEGER NOT NULL,
	"FunctionID" INTEGER NOT NULL,
	"CharacterDelimiterID" INTEGER NOT NULL
)

;
/****** Object:  Table "FUNCTIONDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTIONDESCRIPTION"(
	"FunctionDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "FUNCTIONREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTIONREFERENCE"(
	"FunctionReferenceID" INTEGER NOT NULL,
	"FunctionID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"FunctionReferenceDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "FUNCTIONRELATIONSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTIONRELATIONSHIP"(
	"FunctionRelationshipID" INTEGER NOT NULL,
	"FunctionRelationshipGUID" TEXT NULL,
	"FunctionParentID" INTEGER NOT NULL,
	"FunctionSubjectID" INTEGER NOT NULL,
	"FunctionRelationshipDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "FUNCTIONRELATIONSHIPREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTIONRELATIONSHIPREFERENCE"(
	"FunctionRelationshipReferenceID" INTEGER NOT NULL,
	"FunctionRelationshipGUID" TEXT NULL,
	"FunctionRelationshipID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "FUNCTIONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "FUNCTIONTAG"(
	"FunctionTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "GEOLOCATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GEOLOCATION"(
	"GeoLocationID" INTEGER NOT NULL,
	"GeoLocationGUID" TEXT NULL,
	"room_identifier" TEXT NULL,
	"building_number" TEXT NULL,
	"street_address" TEXT NULL,
	"city" TEXT NULL,
	"state" TEXT NULL,
	"postal_code" TEXT NULL,
	"country" TEXT NULL,
	"latitude" INTEGER NULL,
	"longitude" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CreationObjectGUID" TEXT NULL,
	BLOB TEXT NOT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionMethodGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"LastCheckedDate" TEXT NULL
)

;
/****** Object:  Table "GOOGLEDORK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GOOGLEDORK"(
	"GoogleDorkID" INTEGER NOT NULL,
	"DorkValue" TEXT NULL,
	"DorkExpectedPattern" TEXT NULL,
	"DorkDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "GOOGLEDORKURI"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GOOGLEDORKURI"(
	"GoogleDorkURIID" INTEGER NOT NULL,
	"GoogleDorkID" INTEGER NOT NULL,
	"URIObjectID" INTEGER NOT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "GROUP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GROUP"(
	"GroupID" INTEGER NOT NULL,
	"GroupGUID" TEXT NULL,
	"GroupName" TEXT NULL,
	"GroupDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "GROUPINGRELATIONSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GROUPINGRELATIONSHIP"(
	"GroupingRelationshipID" INTEGER NOT NULL,
	"GroupingRelationshipName" TEXT NOT NULL,
	"GroupingRelationshipDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "GUIACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GUIACTIONNAME"(
	"GUIActionNameID" INTEGER NOT NULL,
	"GUIActionNameName" TEXT NOT NULL,
	"GUIActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "GUIDELINE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GUIDELINE"(
	"GuidelineID" INTEGER NOT NULL,
	"GuidelineGUID" TEXT NULL,
	"GuidelineText" TEXT NOT NULL,
	"GuidelineDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "GUIDELINEFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GUIDELINEFORATTACKPATTERN"(
	"AttackPatternGuidelineID" INTEGER NOT NULL,
	"GuidelineID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"capec_id" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "GUIDIALOGBOX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GUIDIALOGBOX"(
	"GUIDialogboxID" INTEGER NOT NULL
)

;
/****** Object:  Table "GUIOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GUIOBJECT"(
	"GUIObjectID" INTEGER NOT NULL
)

;
/****** Object:  Table "GUIWINDOW"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "GUIWINDOW"(
	"GUIWindowID" INTEGER NOT NULL
)

;
/****** Object:  Table "HANDLETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HANDLETYPE"(
	"HandleTypeID" INTEGER NOT NULL,
	"HandleType" TEXT NOT NULL,
	"HandleTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "HARDWARE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HARDWARE"(
	"HardwareID" INTEGER NOT NULL,
	"DeviceID" INTEGER NULL
)

;
/****** Object:  Table "HASHLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HASHLIST"(
	"HashListID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"RepositoryID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "HASHLISTVALUES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HASHLISTVALUES"(
	"HashListValuesID" INTEGER NOT NULL,
	"HashListID" INTEGER NOT NULL,
	"HashValueID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "HASHNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HASHNAME"(
	"HashNameID" INTEGER NOT NULL,
	"HashingAlgorithmName" TEXT NOT NULL,
	"HashingAlgorithmDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "HASHVALUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HASHVALUE"(
	"HashValueID" INTEGER NOT NULL,
	"HashNameID" INTEGER NULL,
	"HashValueValue" TEXT NOT NULL,
	"CollectedDate" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HEADER"(
	"HeaderID" INTEGER NOT NULL,
	"HeaderGUID" TEXT NULL,
	"HeaderName" TEXT NULL,
	"HeaderDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HEADERDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HEADERDESCRIPTION"(
	"HeaderDescriptionID" INTEGER NOT NULL,
	"HeaderID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HEADERREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HEADERREFERENCE"(
	"HeaderReferenceID" INTEGER NOT NULL,
	"HeaderID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "HEADERTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HEADERTAG"(
	"HeaderTagID" INTEGER NOT NULL,
	"HeaderID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "HIVELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HIVELIST"(
	"HiveListID" INTEGER NOT NULL
)

;
/****** Object:  Table "HOOKING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HOOKING"(
	"HookingID" INTEGER NOT NULL
)

;
/****** Object:  Table "HOOKINGACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HOOKINGACTIONNAME"(
	"HookingActionNameID" INTEGER NOT NULL,
	"HookingActionNameName" TEXT NOT NULL,
	"HookingActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "HOST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HOST"(
	"HostID" INTEGER NOT NULL,
	"ipaddressIPv4" TEXT NULL,
	"macaddress" TEXT NULL,
	"OsName" TEXT NULL,
	"HostService" TEXT NULL,
	"HostVersion" TEXT NULL,
	BLOB TEXT NULL,
	"CPEID" INTEGER NULL
)

;
/****** Object:  Table "HOSTENDPOINT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HOSTENDPOINT"(
	"HostEndPointID" INTEGER NOT NULL,
	"HostPort" INTEGER NULL,
	"HostProtocol" TEXT NULL,
	"HostID" INTEGER NULL,
	"HostService" TEXT NULL,
	"HostVersion" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "HOSTFIELD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HOSTFIELD"(
	"HostFieldID" INTEGER NOT NULL,
	"Domain_Name" TEXT NULL,
	"Port" INTEGER NULL,
	"PortID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "HOSTNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HOSTNAME"(
	"HostNameID" INTEGER NOT NULL,
	"HostNameGUID" TEXT NULL,
	"is_domain_name" INTEGER NULL,
	"Hostname_Value" TEXT NULL,
	"Naming_System" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "HTTPACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPACTIONNAME"(
	"HTTPActionNameID" INTEGER NOT NULL,
	"HTTPActionNameName" TEXT NOT NULL,
	"HTTPActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HTTPCLIENTREQUEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPCLIENTREQUEST"(
	"HTTPClientRequestID" INTEGER NOT NULL,
	"HTTPClientRequestGUID" TEXT NULL,
	"HTTP_Request_Line" INTEGER NULL,
	"HTTP_Request_Header" INTEGER NULL,
	"HTTP_Message_Body" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "HTTPHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPHEADER"(
	"HTTPHeaderID" INTEGER NOT NULL,
	"HTTPHeaderGUID" TEXT NULL,
	"HeaderID" INTEGER NULL,
	"HTTPHeaderName" TEXT NULL,
	"HTTPHeaderDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HTTPHEADERCPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPHEADERCPE"(
	"HTTPHeaderCPEID" INTEGER NOT NULL,
	"CPEID" INTEGER NULL,
	"CPEName" TEXT NOT NULL,
	"HTTPHeaderID" INTEGER NOT NULL,
	"isspecific" INTEGER NULL,
	"isknownvulnerable" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HTTPHEADERDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPHEADERDESCRIPTION"(
	"HTTPHeaderDescriptionID" INTEGER NOT NULL,
	"HTTPHeaderID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "HTTPHEADERPRODUCT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPHEADERPRODUCT"(
	"HTTPHeaderProductID" INTEGER NOT NULL,
	"HTTPHeaderID" INTEGER NULL,
	"HTTPHeaderGUID" TEXT NULL,
	"ProductID" INTEGER NULL,
	"ProductGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "HTTPMESSAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPMESSAGE"(
	"HTTPMessageID" INTEGER NOT NULL,
	"MessageID" INTEGER NULL,
	"Length" INTEGER NULL,
	"Message_Body" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"DiscoveryMethodID" INTEGER NULL,
	"DiscoveryToolID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HTTPMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPMETHOD"(
	"HTTPMethodID" INTEGER NOT NULL,
	"HTTPMethodEnumID" INTEGER NULL
)

;
/****** Object:  Table "HTTPMETHODENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPMETHODENUM"(
	"HTTPMethodEnumID" INTEGER NOT NULL,
	"HTTPMethodName" TEXT NULL,
	"HTTPMethodDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"knowndangerous" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HTTPREQUESTHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPREQUESTHEADER"(
	"HTTPRequestHeaderID" INTEGER NOT NULL,
	"Raw_Header" TEXT NULL,
	"Parsed_Header" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "HTTPREQUESTHEADERFIELDS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPREQUESTHEADERFIELDS"(
	"HTTPRequestHeaderFieldsID" INTEGER NOT NULL,
	"Accept" TEXT NULL,
	"Accept_Charset" TEXT NULL,
	"Accept_Language" TEXT NULL,
	"Accept_Datetime" TEXT NULL,
	"Accept_Encoding" TEXT NULL,
	"AuthorizationHeader" TEXT NULL,
	"Cache_Control" TEXT NULL,
	"Connection" TEXT NULL,
	"Cookie" TEXT NULL,
	"CookieID" INTEGER NULL,
	"Content_Length" INTEGER NULL,
	"Content_MD5" TEXT NULL,
	"Content_Type" TEXT NULL,
	"ContentMIMEID" INTEGER NULL,
	TEXT TEXT NULL,
	"Expect" TEXT NULL,
	"FromHeader" TEXT NULL,
	"FromEmailAddressID" INTEGER NULL,
	"HostFieldID" INTEGER NULL,
	"If_Match" TEXT NULL,
	"If_Modified_Since" TEXT NULL,
	"If_None_Match" TEXT NULL,
	"If_Range" TEXT NULL,
	"If_Unmodified_Since" TEXT NULL,
	"Max_Forwards" INTEGER NULL,
	"Pragma" TEXT NULL,
	"Proxy_Authorization" TEXT NULL,
	"Range" TEXT NULL,
	"Referer" TEXT NULL,
	"RefererURIID" INTEGER NULL,
	"TE" TEXT NULL,
	"User_Agent" TEXT NULL,
	"UserAgentID" INTEGER NULL,
	"Via" TEXT NULL,
	"Warning" TEXT NULL,
	"DNT" TEXT NULL,
	"X_Requested_With" TEXT NULL,
	"X_Forwarded_For" TEXT NULL,
	"X_ATT_DeviceId" TEXT NULL,
	"X_Wap_Profile" TEXT NULL,
	"X_Wap_ProfileURIID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "HTTPREQUESTLINE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPREQUESTLINE"(
	"HTTPRequestLineID" INTEGER NOT NULL,
	"HTTP_Method" INTEGER NULL,
	"Value" TEXT NULL,
	"Version" TEXT NULL,
	"CreationDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "HTTPREQUESTRESPONSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPREQUESTRESPONSE"(
	"HTTPRequestResponseID" INTEGER NOT NULL,
	"HTTPRequestResponseGUID" TEXT NULL,
	"HTTP_Client_Request" INTEGER NULL,
	"HTTP_Server_Response" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "HTTPRESPONSEHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPRESPONSEHEADER"(
	"HTTPResponseHeaderID" INTEGER NOT NULL,
	"Raw_Header" TEXT NULL,
	"Parsed_Header" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL
)

;
/****** Object:  Table "HTTPRESPONSEHEADERFIELDS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPRESPONSEHEADERFIELDS"(
	"HTTPResponseHeaderFieldsID" INTEGER NOT NULL,
	"Access_Control_Allow_Origin" TEXT NULL,
	"Accept_Ranges" TEXT NULL,
	"Age" INTEGER NULL,
	"Cache_Control" TEXT NULL,
	"Connection" TEXT NULL,
	"Content_Encoding" TEXT NULL,
	"Content_Language" TEXT NULL,
	"Content_Length" INTEGER NULL,
	"Content_Location" TEXT NULL,
	"Content_MD5" TEXT NULL,
	"Content_Disposition" TEXT NULL,
	"Content_Range" TEXT NULL,
	"Content_Type" TEXT NULL,
	"ContentMIMEID" INTEGER NULL,
	TEXT TEXT NULL,
	"ETag" TEXT NULL,
	"Expires" TEXT NULL,
	"Last_Modified" TEXT NULL,
	"Link" TEXT NULL,
	"Location" TEXT NULL,
	"LocationURIID" INTEGER NULL,
	"P3P" TEXT NULL,
	"Pragma" TEXT NULL,
	"Proxy_Authenticate" TEXT NULL,
	"Refresh" INTEGER NULL,
	"Retry_After" INTEGER NULL,
	"Server" TEXT NULL,
	"Set_Cookie" TEXT NULL,
	"Strict_Transport_Security" TEXT NULL,
	"Trailer" TEXT NULL,
	"Transfer_Encoding" TEXT NULL,
	"Vary" TEXT NULL,
	"VaryURIID" INTEGER NULL,
	"Via" TEXT NULL,
	"Warning" TEXT NULL,
	"WWW_Authenticate" TEXT NULL,
	"X_Frame_Options" TEXT NULL,
	"X_XSS_Protection" TEXT NULL,
	"X_Content_Type_Options" TEXT NULL,
	"X_Forwarded_Proto" TEXT NULL,
	"X_Powered_By" TEXT NULL,
	"X_UA_Compatible" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "HTTPSERVERRESPONSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPSERVERRESPONSE"(
	"HTTPServerResponseID" INTEGER NOT NULL,
	"HTTP_Status_Line" INTEGER NULL,
	"HTTP_Response_Header" INTEGER NULL,
	"HTTP_Message_Body" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL
)

;
/****** Object:  Table "HTTPSESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPSESSION"(
	"HTTPSessionID" INTEGER NOT NULL,
	"HTTPSessionGUID" TEXT NULL,
	"SessionID" INTEGER NULL,
	"SessionGUID" TEXT NULL,
	"HTTP_Request_ResponseID" INTEGER NULL,
	"HTTPRequestResponseGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "HTTPSESSIONCOOKIE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPSESSIONCOOKIE"(
	"HTTPSessionCookieID" INTEGER NOT NULL,
	"HTTPSessionCookieGUID" TEXT NULL,
	"HTTPSessionID" INTEGER NULL,
	"HTTPSessionGUID" TEXT NULL,
	"HTTPSessionCookieRelationship" TEXT NULL,
	"HTTPSessionDescription" TEXT NULL,
	"CookieID" INTEGER NULL,
	"CookieGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "HTTPSTATUSLINE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HTTPSTATUSLINE"(
	"HTTPStatusLineID" INTEGER NOT NULL,
	"Version" TEXT NULL,
	"VersionID" INTEGER NULL,
	"Status_Code" INTEGER NULL,
	"Reason_Phrase" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "HUMANRISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "HUMANRISK"(
	"HumanRiskID" INTEGER NOT NULL,
	"HumanRiskName" TEXT NOT NULL,
	"HumanRiskDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ICOMHANDLERACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ICOMHANDLERACTION"(
	"IComHandlerActionID" INTEGER NOT NULL,
	"COM_Data" TEXT NULL,
	"COM_Class_ID" TEXT NULL
)

;
/****** Object:  Table "IDENTIFICATIONSYSTEM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IDENTIFICATIONSYSTEM"(
	"IdentificationSystemID" INTEGER NOT NULL,
	"SystemURI" TEXT NOT NULL,
	"IdentifierValueDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "IDENTIFIER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IDENTIFIER"(
	"IdentifierID" INTEGER NOT NULL
)

;
/****** Object:  Table "IDTENTRY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IDTENTRY"(
	"IDTEntryID" INTEGER NOT NULL,
	"Type_Attr" TEXT NULL,
	"Offset_High" TEXT NULL,
	"Offset_Low" TEXT NULL,
	"Offset_Middle" TEXT NULL,
	"Selector" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL
)

;
/****** Object:  Table "IDTENTRYLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IDTENTRYLIST"(
	"IDTEntryListID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "IDTENTRYLISTENTRIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IDTENTRYLISTENTRIES"(
	"IDTEntryListEntriesID" INTEGER NOT NULL,
	"IDTEntryListID" INTEGER NOT NULL,
	"IDTEntryID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL
)

;
/****** Object:  Table "IEXECACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IEXECACTION"(
	"IExecActionID" INTEGER NOT NULL,
	"Exec_Arguments" TEXT NULL,
	"Exec_Program_Path" TEXT NULL,
	"Exec_Working_Directory" TEXT NULL,
	"DirectoryID" INTEGER NULL,
	"Exec_Program_Hashes" TEXT NULL,
	"HashListID" INTEGER NULL
)

;
/****** Object:  Table "IMAGEFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMAGEFILE"(
	"ImageFileID" INTEGER NOT NULL,
	"FileID" INTEGER NULL,
	"ImageFileFormatID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"image_is_compressed" INTEGER NULL,
	"Image_Height" INTEGER NULL,
	"Image_Width" INTEGER NULL,
	"Bits_Per_Pixel" INTEGER NULL,
	"Compression_Algorithm" TEXT NULL,
	"CompressionID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "IMAGEFILEEXIFTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMAGEFILEEXIFTAG"(
	"ImageFileEXIFTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "IMAGEFILEFORMAT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMAGEFILEFORMAT"(
	"ImageFileFormatID" INTEGER NOT NULL,
	"ImageFileFormatName" TEXT NULL,
	"ImageFileFormatDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "IMAGEFILETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMAGEFILETYPE"(
	"ImageFileTypeID" INTEGER NOT NULL,
	"ImageFileTypeName" TEXT NULL,
	"ImageFileTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "IMPACT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMPACT"(
	"ImpactID" INTEGER NOT NULL,
	"TechnicalImpact" INTEGER NULL,
	"BusinessImpact" INTEGER NULL,
	"ImpactName" TEXT NULL,
	"ImpactDescription" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "IMPACTQUALIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMPACTQUALIFICATION"(
	"ImpactQualificationID" INTEGER NOT NULL,
	"ImpactQualificationName" TEXT NULL,
	"ImpactQualificationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "IMPACTRATING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMPACTRATING"(
	"ImpactRatingID" INTEGER NOT NULL,
	"ImpactRatingName" TEXT NULL,
	"ImpactRatingDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "IMPORTANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMPORTANCE"(
	"ImportanceID" INTEGER NOT NULL,
	"ImportanceGUID" TEXT NULL,
	"ImportanceLevel" TEXT NULL,
	"ImportanceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "IMPORTANCETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IMPORTANCETYPE"(
	"ImportanceTypeID" INTEGER NOT NULL,
	"ImportanceTypeName" TEXT NOT NULL,
	"ImportanceTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "INDICATOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATOR"(
	"IndicatorID" INTEGER NOT NULL,
	"IndicatorGUID" TEXT NULL,
	"IndicatorTitle" TEXT NOT NULL,
	"IndicatorDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceLevel" TEXT NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"LikelyImpact" TEXT NULL,
	"Producer" TEXT NULL,
	"negate" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ImportanceID" INTEGER NULL
)

;
/****** Object:  Table "INDICATORENVIRONMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORENVIRONMENT"(
	"IndicatorEnvironmentID" INTEGER NOT NULL,
	"IndicatorEnvironmentGUID" TEXT NULL,
	"IndicatorID" INTEGER NULL,
	"IndicatorGUID" TEXT NULL,
	"EnvironmentID" INTEGER NULL,
	"EnvironmentGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INDICATORFORINDICATOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORFORINDICATOR"(
	"IndicatorRefID" INTEGER NOT NULL,
	"IndicatorSubjectID" INTEGER NOT NULL
)

;
/****** Object:  Table "INDICATORID"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORID"(
	"IndicatorIDID" INTEGER NOT NULL,
	"IndicatorAlternativeID" TEXT NOT NULL,
	"resource" TEXT NULL
)

;
/****** Object:  Table "INDICATORIDFORINCIDENTIOC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORIDFORINCIDENTIOC"(
	"IndicatorIDID" INTEGER NOT NULL,
	"IncidentIOCID" INTEGER NOT NULL
)

;
/****** Object:  Table "INDICATORIDFORINDICATOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORIDFORINDICATOR"(
	"IndicatorIDID" INTEGER NOT NULL,
	"IndicatorID" INTEGER NOT NULL
)

;
/****** Object:  Table "INDICATORTESTMECHANISM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORTESTMECHANISM"(
	"IndicatorTestMechanismID" INTEGER NOT NULL,
	"IndicatorID" INTEGER NULL,
	"TestMechanismID" INTEGER NULL,
	"Product_Name" TEXT NULL,
	"Version" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INDICATORTESTMECHANISMCPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORTESTMECHANISMCPE"(
	"IndicatorTestMechanismCPEID" INTEGER NOT NULL,
	"IndicatorTestMechanismID" INTEGER NULL,
	"CPEID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL
)

;
/****** Object:  Table "INDICATORTESTMECHANISMEVENTFILTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORTESTMECHANISMEVENTFILTER"(
	"IndicatorTestMechanismEventFilterID" INTEGER NOT NULL,
	"IndicatorTestMechanismID" INTEGER NULL,
	"EventFilterID" INTEGER NULL,
	"RuleID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INDICATORTESTMECHANISMEVENTSUPPRESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORTESTMECHANISMEVENTSUPPRESSION"(
	"IndicatorTestMechanismEventSuppressionID" INTEGER NOT NULL,
	"IndicatorTestMechanismID" INTEGER NULL,
	"EventSuppressionID" INTEGER NULL,
	"RuleID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INDICATORTESTMECHANISMRATEFILTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORTESTMECHANISMRATEFILTER"(
	"IndicatorTestMechanismRateFilterID" INTEGER NOT NULL,
	"IndicatorTestMechanismID" INTEGER NULL,
	"RateFilterID" INTEGER NULL,
	"RuleID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INDICATORTESTMECHANISMRULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORTESTMECHANISMRULE"(
	"IndicatorTestMechanismRuleID" INTEGER NOT NULL,
	"IndicatorTestMechanismID" INTEGER NULL,
	"RuleID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "INDICATORTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INDICATORTYPE"(
	"IndicatorTypeID" INTEGER NOT NULL,
	"IndicatorTypeGUID" TEXT NULL,
	"IndicatorTypeName" TEXT NULL,
	"IndicatorTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "INFECTIONPROPAGATIONPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFECTIONPROPAGATIONPROPERTIES"(
	"InfectionPropagationPropertiesID" INTEGER NOT NULL,
	"InfectionPropagationPropertiesName" TEXT NULL,
	"InfectionPropagationPropertiesDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "INFECTIONPROPAGATIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFECTIONPROPAGATIONSTRATEGICOBJECTIVE"(
	"InfectionPropagationStrategicObjectiveID" INTEGER NOT NULL,
	"InfectionPropagationStrategicObjectiveName" TEXT NULL,
	"InfectionPropagationStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INFECTIONPROPAGATIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFECTIONPROPAGATIONTACTICALOBJECTIVE"(
	"InfectionPropagationTacticalObjectiveID" INTEGER NOT NULL,
	"InfectionPropagationTacticalObjectiveName" TEXT NULL,
	"InfectionPropagationTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INFLUENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFLUENCE"(
	"InfluenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "INFORMATIONSOURCEROLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFORMATIONSOURCEROLE"(
	"InformationSourceRoleID" INTEGER NOT NULL,
	"InformationSourceRoleGUID" TEXT NULL,
	"InformationSourceRoleName" TEXT NULL,
	"InformationSourceRoleDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "INFORMATIONSOURCETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFORMATIONSOURCETYPE"(
	"InformationSourceTypeID" INTEGER NOT NULL,
	"InformationSourceTypeGUID" TEXT NULL,
	"InformationSourceTypeName" TEXT NOT NULL,
	"InformationSourceTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "INFORMATIONTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFORMATIONTYPE"(
	"InformationTypeID" INTEGER NOT NULL,
	"InformationTypeGUID" TEXT NULL,
	"InformationTypeName" TEXT NOT NULL,
	"InformationTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INFORMATIONTYPEFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFORMATIONTYPEFORTHREATACTORTTP"(
	"InformationTypeID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL
)

;
/****** Object:  Table "INFRASTRUCTURE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INFRASTRUCTURE"(
	"InfrastructureID" INTEGER NOT NULL,
	"InfrastructureGUID" TEXT NULL,
	"isCritical" INTEGER NULL
)

;
/****** Object:  Table "INJECTIONVECTOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INJECTIONVECTOR"(
	"InjectionVectorID" INTEGER NOT NULL,
	"InjectionVectorGUID" TEXT NULL,
	"InjectionVectorText" TEXT NOT NULL,
	"InjectionVectorDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "INJECTIONVECTORFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INJECTIONVECTORFORATTACKPATTERN"(
	"AttackPatternInjectionVectorID" INTEGER NOT NULL,
	"InjectionVectorID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"capec_id" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INSTANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INSTANCE"(
	"InstanceID" INTEGER NOT NULL,
	"ProcessID" INTEGER NULL
)

;
/****** Object:  Table "INSTRUCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INSTRUCTION"(
	"InstructionID" INTEGER NOT NULL,
	"OpcodeID" INTEGER NOT NULL,
	"Register1ID" INTEGER NULL,
	"Register2ID" INTEGER NULL,
	"InstructionOperand1Value" TEXT NULL,
	"InstructionOperand2Value" TEXT NULL,
	"InstructionHEXValue" TEXT NULL
)

;
/****** Object:  Table "INTEGRITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTEGRITYLEVEL"(
	"IntegrityLevelID" INTEGER NOT NULL,
	"IntegrityLevel" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"IntegrityLevelDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "INTEGRITYVIOLATIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTEGRITYVIOLATIONSTRATEGICOBJECTIVE"(
	"IntegrityViolationStrategicObjectiveID" INTEGER NOT NULL,
	"IntegrityViolationStrategicObjectiveName" TEXT NULL,
	"IntegrityViolationStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INTEGRITYVIOLATIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTEGRITYVIOLATIONTACTICALOBJECTIVE"(
	"IntegrityViolationTacticalObjectiveID" INTEGER NOT NULL,
	"IntegrityViolationTacticalObjectiveName" TEXT NULL,
	"IntegrityViolationTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "INTERACTIONLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTERACTIONLEVEL"(
	"InteractionLevelID" INTEGER NOT NULL,
	"InteractionLevel" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INTERACTIONPOINTS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTERACTIONPOINTS"(
	"InteractionPointsID" INTEGER NOT NULL
)

;
/****** Object:  Table "INTERACTIONPOINTSECURITYCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTERACTIONPOINTSECURITYCONTROL"(
	"InteractionPointSecurityControlID" INTEGER NOT NULL
)

;
/****** Object:  Table "INTERFACE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTERFACE"(
	"InterfaceID" INTEGER NOT NULL,
	"InterfaceName" TEXT NOT NULL,
	"ipaddressIPv4" TEXT NULL,
	"ipaddressIPv6" TEXT NULL,
	"MacAddress" TEXT NULL
)

;
/****** Object:  Table "INTERFACEFORSYSTEMINFO"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTERFACEFORSYSTEMINFO"(
	"SystemInfoID" INTEGER NOT NULL,
	"InterfaceID" INTEGER NOT NULL
)

;
/****** Object:  Table "INTRUSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INTRUSION"(
	"IntrusionID" INTEGER NOT NULL,
	"BreachID" INTEGER NULL
)

;
/****** Object:  Table "INVESTIGATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "INVESTIGATION"(
	"InvestigationID" INTEGER NOT NULL,
	"ProjectID" INTEGER NULL
)

;
/****** Object:  Table "IPCACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPCACTIONNAME"(
	"IPCActionNameID" INTEGER NOT NULL,
	"IPCActionNameName" TEXT NOT NULL,
	"IPCActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "IPFIXDATASET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXDATASET"(
	"IPFIXDataSetID" INTEGER NOT NULL
)

;
/****** Object:  Table "IPFIXMESSAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXMESSAGE"(
	"IPFIXMessageID" INTEGER NOT NULL
)

;
/****** Object:  Table "IPFIXMESSAGEHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXMESSAGEHEADER"(
	"IPFIXMessageHeaderID" INTEGER NOT NULL,
	"VersionNumber" TEXT NULL,
	"Byte_Length" INTEGER NULL,
	"Export_Timestamp" INTEGER NULL,
	"Sequence_Number" INTEGER NULL,
	"Observation_Domain_ID" INTEGER NULL
)

;
/****** Object:  Table "IPFIXOPTIONSTEMPLATERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXOPTIONSTEMPLATERECORD"(
	"IPFIXOptionsTemplateRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "IPFIXOPTIONSTEMPLATERECORDFIELDSPECIFIERS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXOPTIONSTEMPLATERECORDFIELDSPECIFIERS"(
	"IPFIXOptionsTemplateRecordFieldSpecifiersID" INTEGER NOT NULL
)

;
/****** Object:  Table "IPFIXOPTIONSTEMPLATERECORDHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXOPTIONSTEMPLATERECORDHEADER"(
	"IPFIXOptionsTemplateRecordHeaderID" INTEGER NOT NULL,
	"Template_ID" INTEGER NULL,
	"Field_Count" INTEGER NULL,
	"Scope_Field_Count" INTEGER NULL
)

;
/****** Object:  Table "IPFIXOPTIONSTEMPLATESET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXOPTIONSTEMPLATESET"(
	"IPFIXOptionsTemplateSetID" INTEGER NOT NULL,
	"Padding" TEXT NULL
)

;
/****** Object:  Table "IPFIXSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXSET"(
	"IPFIXSetID" INTEGER NOT NULL
)

;
/****** Object:  Table "IPFIXSETHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXSETHEADER"(
	"IPFIXSetHeaderID" INTEGER NOT NULL,
	"Set_ID" INTEGER NULL,
	"Length" INTEGER NULL
)

;
/****** Object:  Table "IPFIXTEMPLATERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXTEMPLATERECORD"(
	"IPFIXTemplateRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "IPFIXTEMPLATERECORDFIELDSPECIFIER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXTEMPLATERECORDFIELDSPECIFIER"(
	"IPFIXTemplateRecordFieldSpecifierID" INTEGER NOT NULL,
	"Enterprise_Bit" INTEGER NULL,
	"Information_Element_ID" TEXT NULL,
	"Field_Length" INTEGER NULL,
	"Enterprise_Number" TEXT NULL
)

;
/****** Object:  Table "IPFIXTEMPLATERECORDHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXTEMPLATERECORDHEADER"(
	"IPFIXTemplateRecordHeaderID" INTEGER NOT NULL,
	"Template_ID" INTEGER NULL,
	"Field_Count" TEXT NULL
)

;
/****** Object:  Table "IPFIXTEMPLATESET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IPFIXTEMPLATESET"(
	"IPFIXTemplateSetID" INTEGER NOT NULL,
	"Padding" TEXT NULL
)

;
/****** Object:  Table "IRCACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "IRCACTIONNAME"(
	"IRCActionNameID" INTEGER NOT NULL,
	"IRCActionNameName" TEXT NOT NULL,
	"IRCActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ISHOWMESSAGEACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ISHOWMESSAGEACTION"(
	"IShowMessageActionID" INTEGER NOT NULL,
	"Show_Message_Body" TEXT NULL,
	"Show_Message_Title" TEXT NULL
)

;
/****** Object:  Table "ISOCURRENCY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ISOCURRENCY"(
	"iso_currency_code" TEXT NOT NULL
)

;
/****** Object:  Table "JOB"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "JOB"(
	"JobID" INTEGER NOT NULL,
	"JobGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ProviderID" INTEGER NULL,
	"DateStart" TEXT NULL,
	"DateEnd" TEXT NULL,
	"Status" TEXT NULL,
	"AgentID" INTEGER NULL,
	"SessionID" INTEGER NULL,
	"AssetSessionID" INTEGER NULL,
	"Parameters" BLOB NULL,
	"XmlResult" BLOB NULL,
	"ErrorReason" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "KERNELHOOK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "KERNELHOOK"(
	"KernelHookID" INTEGER NOT NULL,
	"KernelHookTypeEnumID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "KERNELHOOKTYPEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "KERNELHOOKTYPEENUM"(
	"KernelHookTypeEnumID" INTEGER NOT NULL,
	"KernelHookType" TEXT NULL,
	"KernelHookTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "KEYWORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "KEYWORD"(
	"KeywordID" INTEGER NOT NULL,
	"KeywordValue" TEXT NOT NULL,
	"lang" TEXT NULL
)

;
/****** Object:  Table "KILLCHAIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "KILLCHAIN"(
	"KillChainID" INTEGER NOT NULL,
	"KillChainGID" TEXT NULL,
	"KillChainName" TEXT NOT NULL,
	"KillChainDefiner" TEXT NULL,
	"KillChainReference" TEXT NULL,
	"KillChainNumberOfPhases" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "KILLCHAINFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "KILLCHAINFORTHREATACTORTTP"(
	"KillChainID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL
)

;
/****** Object:  Table "KILLCHAINPHASE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "KILLCHAINPHASE"(
	"KillChainPhaseID" INTEGER NOT NULL,
	"KillChainPhaseGID" TEXT NULL,
	"KillChainPhaseName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "KILLCHAINPHASEFORKILLCHAIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "KILLCHAINPHASEFORKILLCHAIN"(
	"KillChainKillChainPhaseID" INTEGER NOT NULL,
	"KillChainID" INTEGER NOT NULL,
	"KillChainPhaseID" INTEGER NOT NULL,
	"ordinality" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "KILLCHAINPHASEFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "KILLCHAINPHASEFORTHREATACTORTTP"(
	"ThreatActorTTPKillChainPhaseID" INTEGER NOT NULL,
	"KillChainPhaseID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LABEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LABEL"(
	"LabelID" INTEGER NOT NULL
)

;
/****** Object:  Table "LANGUAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LANGUAGE"(
	"LanguageID" INTEGER NOT NULL,
	"LanguageGUID" TEXT NULL,
	"LanguageName" TEXT NULL,
	"LanguageDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LANGUAGECHARACTEREOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LANGUAGECHARACTEREOL"(
	"LanguageCharacterEOLID" INTEGER NOT NULL,
	"LanguageID" INTEGER NOT NULL,
	"CharacterID" INTEGER NOT NULL,
	"ordinal_position" INTEGER NULL
)

;
/****** Object:  Table "LANGUAGECLASS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LANGUAGECLASS"(
	"LanguageClassID" INTEGER NOT NULL,
	"LanguageClassDescription" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LANGUAGEFORAPPLICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LANGUAGEFORAPPLICATION"(
	"ApplicationLanguageID" INTEGER NOT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"LanguageID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LANGUAGEFORTECHNICALCONTEXT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LANGUAGEFORTECHNICALCONTEXT"(
	"TechnicalContextLanguageID" INTEGER NOT NULL,
	"LanguageID" INTEGER NOT NULL,
	"LanguageGUID" TEXT NULL,
	"TechnicalContextID" INTEGER NOT NULL,
	"TechnicalContextGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LANGUAGEFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LANGUAGEFUNCTION"(
	"LanguageFunctionID" INTEGER NOT NULL,
	"LanguageFunctionGUID" TEXT NULL,
	"LanguageID" INTEGER NOT NULL,
	"LanguageGUID" TEXT NULL,
	"FunctionID" INTEGER NOT NULL,
	"FunctionGUID" TEXT NULL,
	"LanguageFunctionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isDeprecated" INTEGER NULL,
	"CreationObjectID" INTEGER NULL,
	"CreationObjectGUID" TEXT NULL,
	"isKnownVulnerable" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionMethodGUID" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceLevelGUID" TEXT NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ConfidenceReasonGUID" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustLevelGUID" TEXT NULL,
	"TrustReasonID" INTEGER NULL,
	"TrustReasonGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"VocabularyGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LANGUAGEFUNCTIONREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LANGUAGEFUNCTIONREFERENCE"(
	"LanguageFunctionReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "LANGUAGEFUNCTIONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LANGUAGEFUNCTIONTAG"(
	"LanguageFunctionTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "LAW"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LAW"(
	"LawID" INTEGER NOT NULL
)

;
/****** Object:  Table "LIBRARY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LIBRARY"(
	"LibraryID" INTEGER NOT NULL
)

;
/****** Object:  Table "LIBRARYACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LIBRARYACTIONNAME"(
	"LibraryActionNameID" INTEGER NOT NULL,
	"LibraryActionNameName" TEXT NOT NULL,
	"LibraryActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "LIBRARYDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LIBRARYDESCRIPTION"(
	"LibraryDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "LIBRARYREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LIBRARYREFERENCE"(
	"LibraryReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "LIBRARYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LIBRARYTAG"(
	"LibraryTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "LICENSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LICENSE"(
	"LicenseID" INTEGER NOT NULL,
	"LicenseName" TEXT NULL,
	"LicenseVersion" TEXT NULL,
	"LicenseTypeID" INTEGER NULL,
	"LicenseDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LICENSEACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LICENSEACCESSRECORD"(
	"LicenseAccessRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "LICENSECHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LICENSECHANGERECORD"(
	"LicenseChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "LICENSERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LICENSERESTRICTION"(
	"LicenseRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "LICENSETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LICENSETYPE"(
	"LicenseTypeID" INTEGER NOT NULL,
	"LicenseTypeName" TEXT NULL,
	"LicenseTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "LINK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LINK"(
	"LinkID" INTEGER NOT NULL,
	"LinkGUID" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"LinkURL" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "LINKTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LINKTYPE"(
	"LinkTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "LINUXPACKAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LINUXPACKAGE"(
	"LinuxPackageID" INTEGER NOT NULL
)

;
/****** Object:  Table "LOCALE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCALE"(
	"LocaleID" INTEGER NOT NULL,
	"LocaleGUID" TEXT NULL,
	"LCIDHex" TEXT NULL,
	"LCIDDec" INTEGER NULL,
	"LocaleValue" TEXT NULL,
	"LocaleDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LOCALEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCALEDESCRIPTION"(
	"LocaleDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "LOCALEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCALEREFERENCE"(
	"LocaleReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "LOCATIONPOINT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCATIONPOINT"(
	"LocationPointID" INTEGER NOT NULL,
	"latitude" INTEGER NOT NULL,
	"longitude" INTEGER NOT NULL,
	"elevation" INTEGER NULL,
	"radius" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LOCATIONPOINTFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCATIONPOINTFORASSET"(
	"LocationPointID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"source" TEXT NULL
)

;
/****** Object:  Table "LOCATIONPOINTFORORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCATIONPOINTFORORGANISATION"(
	"LocationPointID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"source" TEXT NULL
)

;
/****** Object:  Table "LOCATIONPOINTFORPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCATIONPOINTFORPERSON"(
	"LocationPointID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"source" TEXT NULL
)

;
/****** Object:  Table "LOCATIONREGION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCATIONREGION"(
	"LocationRegionID" INTEGER NOT NULL,
	"regionname" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "LOCATIONREGIONFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOCATIONREGIONFORASSET"(
	"LocationRegionID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	BLOB TEXT NOT NULL,
	"source" TEXT NULL
)

;
/****** Object:  Table "LOGFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOGFILE"(
	"LogFileID" INTEGER NOT NULL,
	"FileID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "LOSSDURATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOSSDURATION"(
	"LossDurationID" INTEGER NOT NULL,
	"LossDurationName" TEXT NULL,
	"LossDurationDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "LOSSFACTOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOSSFACTOR"(
	"LossFactorID" INTEGER NOT NULL
)

;
/****** Object:  Table "LOSSFORM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOSSFORM"(
	"LossFormID" INTEGER NOT NULL,
	"LossFormName" TEXT NOT NULL,
	"LossFormDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "LOSSPROPERTY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOSSPROPERTY"(
	"LossPropertyID" INTEGER NOT NULL,
	"LossPropertyGUID" TEXT NULL,
	"LossPropertyName" TEXT NOT NULL,
	"LossPropertyDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "LOSSPROPERTYFORINCIDENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "LOSSPROPERTYFORINCIDENT"(
	"IncidentID" INTEGER NOT NULL,
	"LossPropertyID" INTEGER NOT NULL
)

;
/****** Object:  Table "MACHINEACCESSCONTROLPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MACHINEACCESSCONTROLPROPERTIES"(
	"MachineAccessControlPropertiesID" INTEGER NOT NULL,
	"MachineAccessControlPropertiesName" TEXT NULL,
	"MachineAccessControlPropertiesDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MACHINEACCESSCONTROLSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MACHINEACCESSCONTROLSTRATEGICOBJECTIVE"(
	"MachineAccessControlStrategicObjectiveID" INTEGER NOT NULL,
	"MachineAccessControlStrategicObjectiveName" TEXT NULL,
	"MachineAccessControlStrategicObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "MACHINEACCESSCONTROLTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MACHINEACCESSCONTROLTACTICALOBJECTIVE"(
	"MachineAccessControlTacticalObjectiveID" INTEGER NOT NULL,
	"MachineAccessControlTacticalObjectiveName" TEXT NULL,
	"MachineAccessControlTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "MAINTENANCENOTE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MAINTENANCENOTE"(
	"MaintenanceNoteID" INTEGER NOT NULL,
	"MaintenanceNoteText" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "MANAGEMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MANAGEMENT"(
	"ManagementID" INTEGER NOT NULL,
	"ManagementName" TEXT NULL,
	"ManagementDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "MATURITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MATURITYLEVEL"(
	"MaturityLevelID" INTEGER NOT NULL,
	"MaturityLevelGUID" TEXT NULL,
	"MaturityLevelVocabularyID" TEXT NULL,
	"MaturityLevelName" TEXT NULL,
	"MaturityLevelDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MATURITYRATING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MATURITYRATING"(
	"MaturityRatingID" INTEGER NOT NULL,
	"ScoringSystemID" INTEGER NULL
)

;
/****** Object:  Table "MEASURESOURCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEASURESOURCE"(
	"MeasureSourceID" INTEGER NOT NULL,
	"SourceClassID" INTEGER NULL,
	"SourceClassName" TEXT NULL,
	"MeasureSourceName" TEXT NULL,
	"SourceTypeID" INTEGER NULL,
	"SourceTypeName" TEXT NULL,
	"MeasureSourceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "MEASURESOURCECONTRIBUTOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEASURESOURCECONTRIBUTOR"(
	"MeasureSourceID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "MEASURESOURCEINFORMATIONSOURCETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEASURESOURCEINFORMATIONSOURCETYPE"(
	"MeasureSourceID" INTEGER NOT NULL,
	"InformationSourceTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "MEASURESOURCEPLATFORM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEASURESOURCEPLATFORM"(
	"MeasureSourceID" INTEGER NOT NULL,
	"PlatformID" INTEGER NOT NULL
)

;
/****** Object:  Table "MEASURESOURCESYSTEM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEASURESOURCESYSTEM"(
	"MeasureSourceID" INTEGER NOT NULL,
	"SystemID" INTEGER NOT NULL
)

;
/****** Object:  Table "MEASURESOURCETOOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEASURESOURCETOOL"(
	"MeasureSourceID" INTEGER NOT NULL,
	"ToolInformationID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "MEASURESOURCETOOLTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEASURESOURCETOOLTYPE"(
	"MeasureSourceID" INTEGER NOT NULL,
	"ToolTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "MECHANISM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MECHANISM"(
	"MechanismID" INTEGER NOT NULL,
	"MechanismGUID" TEXT NULL,
	"MechanismName" TEXT NULL,
	"MechanismDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MECHANISMDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MECHANISMDESCRIPTION"(
	"MechanismDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "MECHANISMREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MECHANISMREFERENCE"(
	"MechanismReferenceID" INTEGER NOT NULL,
	"MechanismReferenceGUID" TEXT NULL,
	"MechanismID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "MECHANISMRELATIONSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MECHANISMRELATIONSHIP"(
	"MechanismRelationshipID" INTEGER NOT NULL,
	"MechanismRelationshipGUID" TEXT NULL,
	"MechanismParentID" INTEGER NOT NULL,
	"MechanismSubjectID" INTEGER NOT NULL,
	"MechanismRelationshipDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "MECHANISMTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MECHANISMTAG"(
	"MechanismTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "MEMORYADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEMORYADDRESS"(
	"MemoryAddressID" INTEGER NOT NULL,
	"MemoryAddressGUID" TEXT NULL,
	"MemoryAddressValue" TEXT NOT NULL,
	"MemoryAddressDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "MEMORYADDRESSREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEMORYADDRESSREFERENCE"(
	"MemoryAddressReferenceID" INTEGER NOT NULL,
	"MemoryAddressID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "MEMORYDUMP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEMORYDUMP"(
	"MemoryDumpID" INTEGER NOT NULL
)

;
/****** Object:  Table "MEMORYOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEMORYOBJECT"(
	"MemoryObjectID" INTEGER NOT NULL
)

;
/****** Object:  Table "MEMORYSECTIONLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MEMORYSECTIONLIST"(
	"MemorySectionListID" INTEGER NOT NULL
)

;
/****** Object:  Table "MESSAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MESSAGE"(
	"MessageID" INTEGER NOT NULL,
	"MessageGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "MESSAGECONFIDENTIALITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MESSAGECONFIDENTIALITYLEVEL"(
	"MessageConfidentialityLevelID" INTEGER NOT NULL
)

;
/****** Object:  Table "MESSAGELEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MESSAGELEVEL"(
	"MessageLevelID" INTEGER NOT NULL,
	"MessageLevelValue" TEXT NOT NULL,
	"MessageLevelDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "MESSAGESMS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MESSAGESMS"(
	"MessageSMSID" INTEGER NOT NULL
)

;
/****** Object:  Table "METADATA"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METADATA"(
	"MetadataID" INTEGER NOT NULL,
	"MetadataContent" TEXT NOT NULL,
	"type" TEXT NULL
)

;
/****** Object:  Table "METHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHOD"(
	"MethodID" INTEGER NOT NULL
)

;
/****** Object:  Table "METHODOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHODOLOGY"(
	"MethodologyID" INTEGER NOT NULL,
	"MethodologyGUID" TEXT NULL,
	"MethodologyName" TEXT NOT NULL,
	"MethodologyDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"lang" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"MethodologyReference" TEXT NULL,
	"MethodologyVersion" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "METHODOLOGYCHAPTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHODOLOGYCHAPTER"(
	"MethodologyChapterID" INTEGER NOT NULL,
	"ChapterID" INTEGER NULL
)

;
/****** Object:  Table "METHODOLOGYDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHODOLOGYDESCRIPTION"(
	"MethodologyDescriptionID" INTEGER NOT NULL,
	"MethodologyID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "METHODOLOGYNODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHODOLOGYNODE"(
	"MethodologyNodeID" INTEGER NOT NULL
)

;
/****** Object:  Table "METHODOLOGYREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHODOLOGYREFERENCE"(
	"MethodologyReferenceID" INTEGER NOT NULL,
	"MethodologyID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "METHODOLOGYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHODOLOGYTAG"(
	"MethodologyTagID" INTEGER NOT NULL,
	"MethodologyID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "METHODOLOGYTECHNIQUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHODOLOGYTECHNIQUE"(
	"MethodologyTechniqueID" INTEGER NOT NULL
)

;
/****** Object:  Table "METHODOLOGYTEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METHODOLOGYTEST"(
	"MethodologyTestID" INTEGER NOT NULL,
	"MethodologyTestGUID" TEXT NULL,
	"MethodologyID" INTEGER NULL,
	"MethodologyGUID" TEXT NULL,
	"TestID" INTEGER NULL,
	"TestGUID" TEXT NULL,
	"TestVocabularyID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "METRIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METRIC"(
	"MetricID" INTEGER NOT NULL,
	"MetricGUID" TEXT NULL,
	"MetricName" TEXT NULL,
	"MetricDescription" TEXT NULL,
	"MetricExamples" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "METRICCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METRICCATEGORY"(
	"MetricCategoryID" INTEGER NOT NULL,
	"CategoryID" INTEGER NULL
)

;
/****** Object:  Table "METRICCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METRICCHANGERECORD"(
	"MetricChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "METRICDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METRICDESCRIPTION"(
	"MetricDescriptionID" INTEGER NOT NULL,
	"MetricID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "METRICREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METRICREFERENCE"(
	"MetricReferenceID" INTEGER NOT NULL,
	"MetricID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "METRICTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "METRICTAG"(
	"MetricTagID" INTEGER NOT NULL,
	"MetricID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "MIME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MIME"(
	"MIMEID" INTEGER NOT NULL,
	"MIMEType" TEXT NULL,
	"MIMETypeDescription" TEXT NULL,
	"MIMEVersion" TEXT NULL,
	"MIMETypeReference" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "MIMEVERSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MIMEVERSION"(
	"MIMEVersionID" INTEGER NOT NULL
)

;
/****** Object:  Table "MIMEWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MIMEWHITELIST"(
	"MIMEWhitelistID" INTEGER NOT NULL,
	"MIMEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "MININGSCHEMA"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MININGSCHEMA"(
	"MiningSchemaID" INTEGER NOT NULL,
	"SchemaID" INTEGER NULL
)

;
/****** Object:  Table "MITIGATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATION"(
	"MitigationID" INTEGER NOT NULL,
	"MitigationGUID" TEXT NULL,
	"MitigationVocabularyID" TEXT NULL,
	"MitigationName" TEXT NULL,
	"SolutionMitigationText" TEXT NOT NULL,
	"EffectivenessID" INTEGER NULL,
	"Mitigation_Effectiveness_Notes" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ShortTerm" INTEGER NULL,
	"LongTerm" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONCODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONCODE"(
	"MitigationCodeID" INTEGER NOT NULL,
	"MitigationID" INTEGER NOT NULL,
	"CodeID" INTEGER NOT NULL,
	"Block_Nature" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "MITIGATIONEFFECTIVENESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONEFFECTIVENESS"(
	"MitigationEffectivenessID" INTEGER NOT NULL,
	"MitigationID" INTEGER NULL,
	"EffectivenessID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "MITIGATIONFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONFORATTACKPATTERN"(
	"AttackPatternMitigationID" INTEGER NOT NULL,
	"MitigationID" INTEGER NOT NULL,
	"MitigationGUID" TEXT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONFORCWE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONFORCWE"(
	"CWEMitigationID" INTEGER NOT NULL,
	"MitigationID" INTEGER NOT NULL,
	"MitigationGUID" TEXT NULL,
	"MitigationVocabularyID" TEXT NULL,
	"CWEID" TEXT NOT NULL,
	"MitigationPhaseID" INTEGER NULL,
	"MitigationStrategyID" INTEGER NULL,
	"CWEMitigationDescription" TEXT NULL,
	"EffectivenessID" INTEGER NULL,
	"CWEMitigationEffectivenessNotes" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONPHASE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONPHASE"(
	"MitigationPhaseID" INTEGER NOT NULL,
	"MitigationPhaseGUID" TEXT NULL,
	"PhaseID" INTEGER NULL,
	"PhaseGUID" TEXT NULL,
	"MitigationPhaseName" TEXT NOT NULL,
	"MitigationPhaseDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ImportanceID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONPHASEFORMITIGATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONPHASEFORMITIGATION"(
	"MitigationMitigationPhaseID" INTEGER NOT NULL,
	"MitigationID" INTEGER NOT NULL,
	"MitigationGUID" TEXT NULL,
	"MitigationPhaseID" INTEGER NOT NULL,
	"MitigationPhaseGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONPHASETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONPHASETAG"(
	"MitigationPhaseTagID" INTEGER NOT NULL,
	"MitigationPhaseID" INTEGER NULL,
	"MitigationPhaseGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONREFERENCE"(
	"MitigationReferenceID" INTEGER NOT NULL,
	"MitigationID" INTEGER NOT NULL,
	"MitigationGUID" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"MitigationReferenceDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONSTRATEGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONSTRATEGY"(
	"MitigationStrategyID" INTEGER NOT NULL,
	"MitigationStrategyGUID" TEXT NULL,
	"StrategyID" INTEGER NULL,
	"StrategyGUID" TEXT NULL,
	"MitigationStrategyName" TEXT NULL,
	"MitigationStrategyDescription" TEXT NULL,
	"MitigationStrategyVocabularyID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONSTRATEGYFORMITIGATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONSTRATEGYFORMITIGATION"(
	"MitigationMitigationStrategyID" INTEGER NOT NULL,
	"MitigationID" INTEGER NOT NULL,
	"MitigationGUID" TEXT NULL,
	"MitigationStrategyID" INTEGER NOT NULL,
	"MitigationStrategyGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MITIGATIONSTRATEGYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MITIGATIONSTRATEGYTAG"(
	"MitigationStrategyTagID" INTEGER NOT NULL,
	"MitigationStrategyID" INTEGER NULL,
	"MitigationStrategyGUID" TEXT NULL,
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
/****** Object:  Table "MMSMESSAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MMSMESSAGE"(
	"MMSMessageID" INTEGER NOT NULL,
	"MessageID" INTEGER NULL,
	"SMSMessageID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MOBILEDEVICE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MOBILEDEVICE"(
	"MobileDeviceID" INTEGER NOT NULL,
	"DeviceID" INTEGER NULL
)

;
/****** Object:  Table "MODEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MODEL"(
	"ModelID" INTEGER NOT NULL
)

;
/****** Object:  Table "MODELCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MODELCATEGORY"(
	"ModelCategoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "MODELDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MODELDESCRIPTION"(
	"ModelDescriptionID" INTEGER NOT NULL,
	"ModelID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "MODULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MODULE"(
	"ModuleID" INTEGER NOT NULL,
	"ModuleName" TEXT NULL,
	"ModuleDescription" TEXT NULL,
	"ModuleVersion" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "MUTEX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MUTEX"(
	"MutexID" INTEGER NOT NULL,
	"MutexName" TEXT NULL,
	"MutexDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "MUTEXNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MUTEXNAME"(
	"MutexNameID" INTEGER NOT NULL,
	"MutexID" INTEGER NULL,
	"MutexName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "MUTEXNAMES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MUTEXNAMES"(
	"MutexNamesID" INTEGER NOT NULL,
	"MutexID" INTEGER NOT NULL,
	"MutexNameID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "MUTEXTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "MUTEXTYPE"(
	"MutexTypeID" INTEGER NOT NULL,
	"MutexType" TEXT NULL,
	"MutexTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "NAICS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NAICS"(
	"NAICSID" INTEGER NOT NULL,
	"NAICSSector" TEXT NOT NULL,
	"NAICSDescription" TEXT NOT NULL
)

;
/****** Object:  Table "NAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NAME"(
	"NameID" INTEGER NOT NULL,
	"NameText" TEXT NULL,
	"LocaleID" INTEGER NULL,
	"VersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "NETROUTE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETROUTE"(
	"NetRouteID" INTEGER NOT NULL
)

;
/****** Object:  Table "NETWORK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORK"(
	"NetworkID" INTEGER NOT NULL
)

;
/****** Object:  Table "NETWORKACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKACTIONNAME"(
	"NetworkActionNameID" INTEGER NOT NULL,
	"NetworkActionNameName" TEXT NOT NULL,
	"NetworkActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "NETWORKCONNECTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKCONNECTION"(
	"NetworkConnectionID" INTEGER NOT NULL,
	"NetworkConnectionGUID" TEXT NULL,
	"tls_used" INTEGER NULL,
	"Creation_Time" TEXT NULL,
	"ProtocolLayer3ID" INTEGER NULL,
	"Layer3_Protocol" TEXT NULL,
	"ProtocolLayer4ID" INTEGER NULL,
	"Layer4_Protocol" TEXT NULL,
	"ProtocolLayer7ID" INTEGER NULL,
	"Layer7_Protocol" TEXT NULL,
	"SourceSocketAddressID" INTEGER NULL,
	"SourceTCPStateID" INTEGER NULL,
	"Source_TCP_State" TEXT NULL,
	"DestinationSocketAddressID" INTEGER NULL,
	"DestinationTCPStateID" INTEGER NULL,
	"Destination_TCP_State" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "NETWORKCONNECTIONLAYER7"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKCONNECTIONLAYER7"(
	"NetworkConnectionLayer7ID" INTEGER NOT NULL,
	"NetworkConnectionID" INTEGER NULL,
	"NetworkConnectionGUID" TEXT NULL,
	"HTTPSessionID" INTEGER NULL,
	"HTTPSessionGUID" TEXT NULL,
	"DNSQueryID" INTEGER NULL,
	"DNDQueryGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "NETWORKFLOW"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKFLOW"(
	"NetworkFlowID" INTEGER NOT NULL
)

;
/****** Object:  Table "NETWORKFLOWLABEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKFLOWLABEL"(
	"NetworkFlowLabelID" INTEGER NOT NULL,
	"Src_Socket_Address" INTEGER NULL,
	"Dest_Socket_Address" INTEGER NULL,
	"IP_Protocol" INTEGER NULL,
	"Ingress_Interface_Index" INTEGER NULL,
	"Egress_Interface_Index" INTEGER NULL,
	"IP_Type_Of_Service" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "NETWORKINTERFACE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKINTERFACE"(
	"NetworkInterfaceID" INTEGER NOT NULL
)

;
/****** Object:  Table "NETWORKPACKET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKPACKET"(
	"NetworkPacketID" INTEGER NOT NULL
)

;
/****** Object:  Table "NETWORKROUTE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKROUTE"(
	"NetworkRouteID" INTEGER NOT NULL,
	"NetworkRouteGUID" TEXT NULL,
	"NetRouteID" INTEGER NULL,
	"is_ipv6" INTEGER NULL,
	"is_autoconfigure_address" INTEGER NULL,
	"is_immortal" INTEGER NULL,
	"is_loopback" INTEGER NULL,
	"is_publish" INTEGER NULL,
	"DestinationAddressID" INTEGER NULL,
	"OriginAddressID" INTEGER NULL,
	"NetmaskID" INTEGER NULL,
	"GatewayAddressID" INTEGER NULL,
	"Metric" INTEGER NULL,
	"NetworkRouteTypeID" INTEGER NULL,
	"NetworkRouteType" TEXT NULL,
	"ProtocolID" INTEGER NULL,
	"NetworkRouteProtocol" TEXT NULL,
	"NetworkRouteInterface" TEXT NULL,
	"PreferredLifetime" INTEGER NULL,
	"ValidLifetime" INTEGER NULL,
	"RouteAge" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "NETWORKROUTEENTRY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKROUTEENTRY"(
	"NetworkRouteEntryID" INTEGER NOT NULL
)

;
/****** Object:  Table "NETWORKROUTETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKROUTETYPE"(
	"NetworkRouteTypeID" INTEGER NOT NULL,
	"RouteType" TEXT NULL,
	"RouteTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "NETWORKSHARE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKSHARE"(
	"NetworkShareID" INTEGER NOT NULL,
	"NetworkShareGUID" TEXT NULL
)

;
/****** Object:  Table "NETWORKSHAREACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKSHAREACTIONNAME"(
	"NetworkShareActionNameID" INTEGER NOT NULL,
	"NetworkShareActionNameName" TEXT NOT NULL,
	"NetworkShareActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "NETWORKSOCKET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKSOCKET"(
	"NetworkSocketID" INTEGER NOT NULL
)

;
/****** Object:  Table "NETWORKSUBNET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKSUBNET"(
	"NetworkSubnetID" INTEGER NOT NULL,
	"NetworkSubnetGUID" TEXT NULL,
	"NetworkSubnetName" TEXT NULL,
	"NetworkSubnetDescription" TEXT NULL,
	"NetworkSubnetNumberOfIPAddresses" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "NETWORKSUBNETROUTES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKSUBNETROUTES"(
	"NetworkSubnetRoutesID" INTEGER NOT NULL,
	"NetworkSubnetID" INTEGER NULL,
	"NetworkSubnetGUID" TEXT NULL,
	"NetworkRouteID" INTEGER NULL,
	"NetworkRouteGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "NETWORKZONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKZONE"(
	"NetworkZoneID" INTEGER NOT NULL,
	"NetworkZoneGUID" TEXT NULL,
	"ZoneID" INTEGER NULL,
	"ZoneGUID" TEXT NULL,
	"NetworkZoneName" TEXT NULL,
	"NetworkZoneDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "NETWORKZONEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKZONEDESCRIPTION"(
	"NetworkZoneDescriptionID" INTEGER NOT NULL,
	"NetworkZoneID" INTEGER NULL,
	"NetworkZoneGUID" TEXT NULL,
	"DescriptionID" INTEGER NULL,
	"DescriptionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "NETWORKZONERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKZONERESTRICTION"(
	"NetworkZoneRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "NETWORKZONETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NETWORKZONETAG"(
	"NetworkZoneTagID" INTEGER NOT NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "NEURALNETWORK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NEURALNETWORK"(
	"NeuralNetworkID" INTEGER NOT NULL
)

;
/****** Object:  Table "NOTIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "NOTIFICATION"(
	"NotificationID" INTEGER NOT NULL,
	"NotificationGUID" TEXT NULL,
	BLOB TEXT NULL,
	"UserID" TEXT NULL,
	"NotificationMessage" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OBFUSCATIONTECHNIQUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBFUSCATIONTECHNIQUE"(
	"ObfuscationTechniqueID" INTEGER NOT NULL,
	"ObfuscationTechniqueGUID" TEXT NULL,
	"TechniqueID" INTEGER NULL,
	"ObfuscationTechniqueName" TEXT NOT NULL,
	"ObfuscationTechniqueDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OBFUSCATIONTECHNIQUETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBFUSCATIONTECHNIQUETAG"(
	"ObfuscationTechniqueTagID" INTEGER NOT NULL,
	"ObfuscationTechniqueID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBJECTIVE"(
	"ObjectiveID" INTEGER NOT NULL,
	"ObjectiveGUID" TEXT NULL,
	"ObjectiveCategoryID" INTEGER NULL,
	"ObjectiveVocabularyID" TEXT NULL,
	"ObjectiveName" TEXT NULL,
	"ObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OBJECTIVECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBJECTIVECATEGORY"(
	"ObjectiveCategoryID" INTEGER NOT NULL,
	"ObjectiveCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"ObjectiveCategoryName" TEXT NULL,
	"ObjectiveCategoryDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OBJECTIVETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBJECTIVETAG"(
	"ObjectiveTagID" INTEGER NOT NULL,
	"ObjectiveID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OBJECTRELATIONSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBJECTRELATIONSHIP"(
	"ObjectRelationshipID" INTEGER NOT NULL,
	"ObjectRelationshipName" TEXT NOT NULL,
	"ObjectRelationshipDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "OBJECTSTATE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBJECTSTATE"(
	"ObjectStateID" INTEGER NOT NULL,
	"ObjectStateName" TEXT NOT NULL,
	"ObjectStateDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "OBJECTTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBJECTTYPE"(
	"ObjectTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OBSERVATIONMETHOD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OBSERVATIONMETHOD"(
	"ObservationMethodID" INTEGER NOT NULL,
	"ObservationMethodGUID" TEXT NULL,
	"ObservationMethodName" TEXT NOT NULL,
	"ObservationMethodDescription" TEXT NULL,
	"MeasureSourceID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OFFSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OFFSET"(
	"OffsetID" INTEGER NOT NULL
)

;
/****** Object:  Table "ONTOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ONTOLOGY"(
	"OntologyID" INTEGER NOT NULL
)

;
/****** Object:  Table "OPCODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OPCODE"(
	"OpcodeID" INTEGER NOT NULL,
	"OpcodeName" TEXT NOT NULL,
	"OpcodeDescription" TEXT NULL,
	"OpcodeHEXValue" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OPCODEFORCPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OPCODEFORCPE"(
	"CPEID" TEXT NOT NULL,
	"OpcodeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OPERATIONENUMERATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OPERATIONENUMERATION"(
	"OperationEnumerationID" INTEGER NOT NULL,
	"OperationValue" TEXT NOT NULL,
	"OperationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OPERATIONENUMERATIONFORSIMPLEDATATYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OPERATIONENUMERATIONFORSIMPLEDATATYPE"(
	"SimpleDataTypeID" INTEGER NOT NULL,
	"OperationEnumerationID" INTEGER NOT NULL
)

;
/****** Object:  Table "OPERATORENUMERATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OPERATORENUMERATION"(
	"OperatorEnumerationID" INTEGER NOT NULL,
	"OperatorValue" TEXT NOT NULL,
	"OperatorDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATION"(
	"OrganisationID" INTEGER NOT NULL,
	"OrganisationGUID" TEXT NULL,
	"OrganisationName" TEXT NOT NULL,
	"OrganisationType" TEXT NULL,
	"OrganisationKnownAs" TEXT NULL,
	"industry" TEXT NULL,
	"CountryID" INTEGER NULL,
	"employee_count" TEXT NULL,
	"revenueamount" INTEGER NULL,
	"iso_currency_code" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ORGANISATIONACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONACCESSRECORD"(
	"OrganisationAccessRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "ORGANISATIONCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONCHANGERECORD"(
	"OrganisationChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "ORGANISATIONDOMAINNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONDOMAINNAME"(
	"OrganisationDomainNameID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"OrganisationGUID" TEXT NULL,
	"OrganisationDomainNameRelationship" TEXT NULL,
	"DomainNameID" INTEGER NULL,
	"DomainNameGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ORGANISATIONFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONFORTHREATACTORTTP"(
	"ThreatActorTTPOrganisationID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"ThreatActorTTPGUID" TEXT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"OrganisationGUID" TEXT NULL,
	"Information_Source" TEXT NULL,
	"ConfidenceLevel" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"notes" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ORGANISATIONLICENSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONLICENSE"(
	"OrganisationLicenseID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"LicenseID" INTEGER NOT NULL
)

;
/****** Object:  Table "ORGANISATIONPOLICY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONPOLICY"(
	"OrganisationPolicyID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"PolicyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "ORGANISATIONPROJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONPROJECT"(
	"OrganisationProjectID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"OrganisationGUID" TEXT NULL,
	"OrganisationProjectRelationship" TEXT NULL,
	"OrganisationProjectDescription" TEXT NULL,
	"ProjectID" INTEGER NULL,
	"ProjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromdate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ORGANISATIONSCHEDULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
/****** Object:  Table "ORGANISATIONRISKSCORE"    Script Date: 06/20/2026 00:00:00 ******/

CREATE TABLE "ORGANISATIONRISKSCORE"(
	"EnterpriseRiskScoreID" INTEGER NOT NULL,
	"CreatedDate" DATE NULL,
	"OrganisationID" INTEGER NULL,
	"RiskScore" REAL NULL
)

;
/****** Object:  Table "TOOLSTAR" (per-user GitHub-style stars on the TOOL catalogue) ******/

;
CREATE TABLE "TOOLSTAR"(
	"StarID" INTEGER PRIMARY KEY,
	"ToolID" INTEGER NOT NULL,
	"UserID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL
)

;
CREATE UNIQUE INDEX IF NOT EXISTS ux_toolstar_user_tool ON "TOOLSTAR"("UserID","ToolID")

;
CREATE INDEX IF NOT EXISTS ix_toolstar_tool ON "TOOLSTAR"("ToolID")

;
CREATE TABLE "ORGANISATIONSCHEDULE"(
	"OrganisationScheduleID" INTEGER NOT NULL
)

;
/****** Object:  Table "ORGANISATIONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONTAG"(
	"OrganisationTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "ORGANISATIONTECHNOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONTECHNOLOGY"(
	"OrganisationTechnologyID" INTEGER NOT NULL
)

;
/****** Object:  Table "ORGANISATIONWORKINGHOURS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANISATIONWORKINGHOURS"(
	"OrganisationWorkingHoursID" INTEGER NOT NULL
)

;
/****** Object:  Table "ORGANIZATIONALUNIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANIZATIONALUNIT"(
	"OrganizationalUnitID" INTEGER NOT NULL,
	"OrganizationalUnitGUID" TEXT NULL,
	"OUName" TEXT NOT NULL,
	"OUDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ORGANIZATIONALUNITFORORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANIZATIONALUNITFORORGANISATION"(
	"OrganisationUnitsID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"OrganisationGUID" TEXT NULL,
	"OrganizationalUnitID" INTEGER NOT NULL,
	"OrganizationalUnitGUID" TEXT NULL,
	"OUChildName" TEXT NULL,
	"OUChildDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ORGANIZATIONALUNITPOLICY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ORGANIZATIONALUNITPOLICY"(
	"OrganizationalUnitPolicyID" INTEGER NOT NULL,
	"OrganizationalUnitID" INTEGER NOT NULL,
	"OrganizationalUnitGUID" TEXT NULL,
	"OrganizationalUnitRelationship" TEXT NULL,
	"PolicyID" INTEGER NOT NULL,
	"PolicyGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OS"(
	"OSID" INTEGER NOT NULL,
	"Operating_System_Name" TEXT NULL,
	"OSname" TEXT NOT NULL,
	"OSversion" TEXT NULL,
	"LocaleID" INTEGER NULL,
	"OSlang" TEXT NULL,
	"OSSP" TEXT NULL,
	"Platform" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OSCLASS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSCLASS"(
	"OSClassID" INTEGER NOT NULL,
	"OSClassGUID" TEXT NULL,
	"Operating_System_Class_Description" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OSFAMILY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSFAMILY"(
	"OSFamilyID" INTEGER NOT NULL,
	"FamilyName" TEXT NULL,
	"FamilyDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OSFAMILYFOROS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSFAMILYFOROS"(
	"OSFamilyOSID" INTEGER NOT NULL,
	"OSID" INTEGER NOT NULL,
	"OSFamilyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "OSFAMILYPLATFORM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSFAMILYPLATFORM"(
	"OSFamilyPlatformID" INTEGER NOT NULL,
	"OSFamilyID" INTEGER NULL,
	"PlatformID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OSILAYER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSILAYER"(
	"OSILayerID" INTEGER NOT NULL,
	"OSILayerName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OSILAYERFORATTACKSURFACE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSILAYERFORATTACKSURFACE"(
	"AttackSurfaceOSILayerID" INTEGER NOT NULL,
	"OSILayerID" INTEGER NOT NULL,
	"AttackSurfaceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "OSINSTRUCTIONMEMORYADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSINSTRUCTIONMEMORYADDRESS"(
	"OSInstructionMemoryAddressID" INTEGER NOT NULL,
	"OSID" INTEGER NOT NULL,
	"InstructionID" INTEGER NOT NULL,
	"MemoryAddressID" INTEGER NOT NULL,
	"OSPatchLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OSPATCH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSPATCH"(
	"OSPatchID" INTEGER NOT NULL,
	"OSPatchGUID" TEXT NULL,
	"OSID" INTEGER NULL,
	"OSGUID" TEXT NULL,
	"PatchID" INTEGER NULL,
	"PatchGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionMethodGUID" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustLevelGUID" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OSPATCHLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSPATCHLEVEL"(
	"OSPatchLevelID" INTEGER NOT NULL,
	"OSPatchLevelGUID" TEXT NOT NULL,
	"OSPatchLevelDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "OSPATCHLEVELPATCH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OSPATCHLEVELPATCH"(
	"OSPatchesID" INTEGER NOT NULL,
	"OSPatchLevelID" INTEGER NOT NULL,
	"OSPatchID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OUTPUTFIELD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OUTPUTFIELD"(
	"OutputFieldID" INTEGER NOT NULL,
	"FieldID" INTEGER NULL
)

;
/****** Object:  Table "OWASPTOP10"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10"(
	"OWASPTOP10ID" INTEGER NOT NULL,
	"OWASPTOP10GUID" TEXT NULL,
	"OWASPTOP10RefID" TEXT NULL,
	"OWASPName" TEXT NOT NULL,
	"OWASPDescription" TEXT NULL,
	"Detectability" TEXT NULL,
	"Rank" INTEGER NOT NULL,
	"YearTop10" INTEGER NULL,
	"ReferenceURL" TEXT NULL,
	"OWASPTOP10Type" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "OWASPTOP10ATTACKVECTOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10ATTACKVECTOR"(
	"OWASPTOP10ID" INTEGER NOT NULL,
	"AttackVectorID" INTEGER NOT NULL,
	"ExploitabilityLevel" TEXT NULL
)

;
/****** Object:  Table "OWASPTOP10DEFENSETOOLTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10DEFENSETOOLTYPE"(
	"OWASPTOP10ID" INTEGER NOT NULL,
	"DefenseToolTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OWASPTOP10DETECTABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10DETECTABILITY"(
	"OWASPTOP10ID" INTEGER NOT NULL,
	"DetectabilityID" INTEGER NOT NULL
)

;
/****** Object:  Table "OWASPTOP10EXPLOITABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10EXPLOITABILITY"(
	"OWASPTOP10ExploitabilityID" INTEGER NOT NULL,
	"OWASPTOP10ID" INTEGER NOT NULL,
	"ExploitabilityID" INTEGER NOT NULL
)

;
/****** Object:  Table "OWASPTOP10IMPACT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10IMPACT"(
	"OWASPTOP10ID" INTEGER NOT NULL,
	"ImpactID" INTEGER NOT NULL,
	"ImpactSeverity" TEXT NULL
)

;
/****** Object:  Table "OWASPTOP10MAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10MAPPING"(
	"OWASPTOP10MappingID" INTEGER NOT NULL,
	"OWASPTOP10RefID" INTEGER NOT NULL,
	"OWASPNameRef" TEXT NULL,
	"RankRef" INTEGER NULL,
	"YearRef" INTEGER NULL,
	"OWASPTOP10SubjectID" INTEGER NOT NULL,
	"OWASPNameSubject" TEXT NULL,
	"RankSubject" INTEGER NULL,
	"YearSubject" INTEGER NULL,
	"CreationDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OWASPTOP10PREVALENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10PREVALENCE"(
	"OWASPTOP10ID" INTEGER NOT NULL,
	"PrevalenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "OWASPTOP10REFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10REFERENCE"(
	"OWASPTOP10ID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "OWASPTOP10TOOLINFORMATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWASPTOP10TOOLINFORMATION"(
	"OWASPTOP10ID" INTEGER NOT NULL,
	"ToolInformationID" INTEGER NOT NULL,
	"Relationship" TEXT NULL
)

;
/****** Object:  Table "OWNERSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "OWNERSHIP"(
	"OwnershipID" INTEGER NOT NULL,
	"OwnershipName" TEXT NULL,
	"OwnershipDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "PACKAGEINTENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PACKAGEINTENT"(
	"PackageIntentID" INTEGER NOT NULL,
	"PackageIntentGUID" TEXT NULL,
	"PackageIntentName" TEXT NULL,
	"PackageIntentDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromdate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "PACKAGING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PACKAGING"(
	"PackagingID" INTEGER NOT NULL,
	"PackagingGUID" TEXT NULL,
	"PackagingLayerName" TEXT NOT NULL,
	"PackagingDescription" TEXT NULL,
	"is_encrypted" INTEGER NULL,
	"is_compressed" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"RepositoryID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "PACKAGINGCOMPRESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PACKAGINGCOMPRESSION"(
	"PackagingCompressionID" INTEGER NOT NULL,
	"PackagingCompressionGUID" TEXT NULL,
	"PackagingCompressionDescription" TEXT NULL,
	"PackagingID" INTEGER NOT NULL,
	"PackagingGUID" TEXT NULL,
	"CompressionID" INTEGER NOT NULL,
	"CompressionGUID" TEXT NULL,
	"LayerOrder" INTEGER NOT NULL,
	"CompressionPassword" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PACKAGINGENCODING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PACKAGINGENCODING"(
	"PackagingEncodingID" INTEGER NOT NULL,
	"PackagingEncodingGUID" TEXT NULL,
	"PackagingID" INTEGER NOT NULL,
	"PackagingGUID" TEXT NULL,
	"EncodingID" INTEGER NOT NULL,
	"EncodingGUID" TEXT NULL,
	"LayerOrder" INTEGER NOT NULL,
	"algorithm" TEXT NULL,
	"character_set" TEXT NULL,
	"CharacterSetID" INTEGER NULL,
	"custom_character_set_ref" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PACKAGINGENCRYPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PACKAGINGENCRYPTION"(
	"PackagingEncryptionID" INTEGER NOT NULL,
	"PackagingEncryptionGUID" TEXT NULL,
	"PackagingID" INTEGER NOT NULL,
	"PackagingGUID" TEXT NULL,
	"EncryptionID" INTEGER NOT NULL,
	"EncryptionGUID" TEXT NULL,
	"LayerOrder" INTEGER NOT NULL,
	"encryption_key" TEXT NULL,
	"encryption_key_ref" TEXT NULL,
	"PackagingEncryptionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PARAGRAPH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PARAGRAPH"(
	"ParagraphID" INTEGER NOT NULL,
	"SectionID" INTEGER NULL
)

;
/****** Object:  Table "PARAMETER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PARAMETER"(
	"ParameterID" INTEGER NOT NULL
)

;
/****** Object:  Table "PARAMETERDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PARAMETERDESCRIPTION"(
	"ParameterDescriptionID" INTEGER NOT NULL,
	"ParameterID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PARAMETERSFORPROVIDER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PARAMETERSFORPROVIDER"(
	"ID" INTEGER NOT NULL,
	"ServiceCategoryID" INTEGER NOT NULL,
	"Strategy" TEXT NULL,
	"Policy" TEXT NULL,
	"ProviderID" INTEGER NOT NULL,
	"Parameters" TEXT NULL
)

;
/****** Object:  Table "PARAMETERTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PARAMETERTAG"(
	"ParameterTagID" INTEGER NOT NULL,
	"ParameterID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PASSWORDQUESTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PASSWORDQUESTION"(
	"PasswordQuestionID" INTEGER NOT NULL,
	"Label" TEXT NULL,
	"Value" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PATCH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PATCH"(
	"PatchID" INTEGER NOT NULL,
	"PatchGUID" TEXT NULL,
	"PatchVocabularyID" TEXT NULL,
	"PatchTitle" TEXT NULL,
	"PatchDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PATCHFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PATCHFILE"(
	"PatchFileID" INTEGER NOT NULL
)

;
/****** Object:  Table "PATCHREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PATCHREFERENCE"(
	"PatchReferenceID" INTEGER NOT NULL,
	"PatchID" INTEGER NOT NULL,
	"PatchGUID" TEXT NULL,
	"PatchReferenceRelationship" TEXT NULL,
	"PatchReferenceDescription" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PATCHREPOSITORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PATCHREPOSITORY"(
	"PatchRepositoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "PATTERNFIELDGROUP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PATTERNFIELDGROUP"(
	"PatternFieldGroupID" INTEGER NOT NULL,
	"ConditionApplicationID" INTEGER NULL,
	"apply_condition" TEXT NULL,
	"bit_mask" TEXT NULL,
	"ConditionID" INTEGER NULL,
	"condition" TEXT NULL,
	"has_changed" INTEGER NULL,
	"PatternTypeID" INTEGER NULL,
	"pattern_type" TEXT NULL,
	"regex_syntax" TEXT NULL,
	"trend" INTEGER NULL
)

;
/****** Object:  Table "PATTERNTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PATTERNTYPE"(
	"PatternTypeID" INTEGER NOT NULL,
	"PatternTypeName" TEXT NOT NULL,
	"PatternTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PAYLOAD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PAYLOAD"(
	"PayloadID" INTEGER NOT NULL,
	"AttackPayloadID" INTEGER NULL,
	"PayloadGUID" TEXT NULL,
	"PayloadName" TEXT NULL,
	"PayloadText" TEXT NULL,
	"PayloadDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PCAPFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PCAPFILE"(
	"PCAPFileID" INTEGER NOT NULL,
	"FileID" INTEGER NULL
)

;
/****** Object:  Table "PDFFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PDFFILE"(
	"PDFFileID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERFORMANCEREQUIREMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERFORMANCEREQUIREMENT"(
	"PerformanceRequirementID" INTEGER NOT NULL,
	"RequirementID" INTEGER NULL,
	"RequirementGUID" TEXT NULL,
	"PerformanceRequirementGUID" TEXT NULL,
	"PerformanceRequirementTitle" TEXT NULL,
	"PerformanceRequirementDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PERIMETER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERIMETER"(
	"PerimeterID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERIMETERDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERIMETERDESCRIPTION"(
	"PerimeterDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERIMETERZONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERIMETERZONE"(
	"PerimeterZoneID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERMISSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERMISSION"(
	"PermissionID" INTEGER NOT NULL,
	"PermissionName" TEXT NULL,
	"PermissionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"CreationObjectID" INTEGER NULL
)

;
/****** Object:  Table "PERMISSIONDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERMISSIONDESCRIPTION"(
	"PermissionDescriptionID" INTEGER NOT NULL,
	"PermissionID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERSISTENCEPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSISTENCEPROPERTIES"(
	"PersistencePropertiesID" INTEGER NOT NULL,
	"PersistencePropertiesName" TEXT NULL,
	"PersistencePropertiesDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSISTENCESTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSISTENCESTRATEGICOBJECTIVE"(
	"PersistenceStrategicObjectiveID" INTEGER NOT NULL,
	"PersistenceStrategicObjectiveName" TEXT NULL,
	"PersistenceStrategicObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSISTENCETACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSISTENCETACTICALOBJECTIVE"(
	"PersistenceTacticalObjectiveID" INTEGER NOT NULL,
	"PersistenceTacticalObjectiveName" TEXT NULL,
	"PersistenceTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "PERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSON"(
	"PersonID" INTEGER NOT NULL,
	"PrecedingTitle" TEXT NULL,
	"Title" TEXT NULL,
	"FirstName" TEXT NULL,
	"MiddleName" TEXT NULL,
	"LastNamePrefix" TEXT NULL,
	"LastName" TEXT NULL,
	"FullName" TEXT NULL,
	"OtherName" TEXT NULL,
	"Alias" TEXT NULL,
	"Suffix" TEXT NULL,
	"GeneralSuffix" TEXT NULL,
	"PersonFunction" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ModifiedDate" TEXT NULL,
	"birthdate" TEXT NULL,
	BLOB TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"email" TEXT NULL,
	-- Org-chart / directory fields, aligned with Microsoft Entra ID / Active Directory (see /org-chart)
	"ManagerPersonID" INTEGER NULL,    -- org-chart parent edge (Entra/AD manager)
	"JobTitle" TEXT NULL, "Department" TEXT NULL, "CompanyName" TEXT NULL, "OfficeLocation" TEXT NULL,
	"UserPrincipalName" TEXT NULL, "EmployeeID" TEXT NULL, "EmployeeType" TEXT NULL,
	"EntraObjectID" TEXT NULL, "ObjectGUID" TEXT NULL, "OnPremisesSamAccountName" TEXT NULL,
	"UsageLocation" TEXT NULL, "MobilePhone" TEXT NULL, "BusinessPhone" TEXT NULL, "AccountEnabled" INTEGER NULL,
	"TenantID" INTEGER NULL    -- tenant scope (PERSON was historically a global directory)
)

;
/****** Object:  Table "PERSONASSURANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONASSURANCE"(
	"PersonAssuranceID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERSONBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONBLACKLIST"(
	"PersonBlacklistID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"PhysicalLocationID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "PERSONCERTIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONCERTIFICATION"(
	"PersonCertificationID" INTEGER NOT NULL,
	"PersonID" INTEGER NULL,
	"CertificationID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSONDEVICE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONDEVICE"(
	"PersonDeviceID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"DeviceID" INTEGER NOT NULL,
	BLOB TEXT NULL,
	"RACIValue" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "PERSONDOMAINNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONDOMAINNAME"(
	"PersonDomainNameID" INTEGER NOT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"PersonDomainNameRelationship" TEXT NULL,
	"DomainNameID" INTEGER NULL,
	"DomainNameGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSONFORAPPLICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONFORAPPLICATION"(
	"ApplicationID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"RelationShip" TEXT NULL,
	"RACIValue" TEXT NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "PERSONFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONFORASSET"(
	"PersonID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"relationshiptype" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"RACIValue" TEXT NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "PERSONFORINCIDENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONFORINCIDENT"(
	"IncidentPersonID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"IncidentPersonRole" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PERSONFORORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONFORORGANISATION"(
	"PersonOrganisationID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"relationshiptype" TEXT NOT NULL,
	"ScheduleID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"RACIValue" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSONFORPERSONGROUP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONFORPERSONGROUP"(
	"PersonGroupPersonID" INTEGER NOT NULL,
	"PersonGroupID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PERSONFORPROJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONFORPROJECT"(
	"ProjectPersonID" INTEGER NOT NULL,
	"ProjectID" INTEGER NOT NULL,
	"ProjectGUID" TEXT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonGUID" TEXT NULL,
	"PersonRole" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSONFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONFORTHREATACTORTTP"(
	"ThreatActorTTPPersonID" INTEGER NOT NULL,
	"ThreatActorTTPPersonGUID" TEXT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonGUID" TEXT NULL,
	"ThreatActorTTPPersonRelationship" TEXT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"ThreatActorTTPGUID" TEXT NULL,
	"Information_Source" TEXT NULL,
	"ConfidenceLevel" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"notes" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PERSONGEOLOCATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONGEOLOCATION"(
	"PersonGeoLocationID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonGUID" TEXT NULL,
	"GeoLocationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSONGROUP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONGROUP"(
	"PersonGroupID" INTEGER NOT NULL,
	"PersonGroupName" TEXT NOT NULL,
	"PersonGroupDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "PERSONLICENSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONLICENSE"(
	"PersonLicenseID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonGUID" TEXT NULL,
	"LicenseID" INTEGER NOT NULL,
	"LicenseGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSONPERMISSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONPERMISSION"(
	"PersonPermissionID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"PermissionID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERSONPHYSICALLOCATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONPHYSICALLOCATION"(
	"PersonPhysicalLocationID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonGUID" TEXT NULL,
	"PhysicalLocationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSONSCHEDULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONSCHEDULE"(
	"PersonScheduleID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERSONSKILL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONSKILL"(
	"PersonSkillID" INTEGER NOT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"SkillID" INTEGER NULL,
	"SkillGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PERSONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONTAG"(
	"PersonTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "PERSONWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONWHITELIST"(
	"PersonWhitelistID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"PhysicalLocationID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "PERSONWORKINGHOURS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PERSONWORKINGHOURS"(
	"PersonWorkingHoursID" INTEGER NOT NULL
)

;
/****** Object:  Table "PGPSIGNATURE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PGPSIGNATURE"(
	"PGPSignatureID" INTEGER NOT NULL,
	"SignatureID" INTEGER NULL
)

;
/****** Object:  Table "PHASE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHASE"(
	"PhaseID" INTEGER NOT NULL,
	"PhaseGUID" TEXT NULL,
	"PhaseName" TEXT NULL,
	"PhaseDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PHASEMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHASEMAPPING"(
	"PhaseMappingID" INTEGER NOT NULL,
	"PhaseRefID" INTEGER NULL,
	"PhaseRefGUID" TEXT NULL,
	"PhaseRelationship" TEXT NULL,
	"PhaseMappingDescription" TEXT NULL,
	"PhaseSubjectID" INTEGER NULL,
	"PhaseSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PHASETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHASETAG"(
	"PhaseTagID" INTEGER NOT NULL,
	"PhaseID" INTEGER NULL,
	"PhaseGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PHONECALL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHONECALL"(
	"PhoneCallID" INTEGER NOT NULL,
	"TelephoneCallID" INTEGER NULL,
	"duration" TEXT NULL,
	"isSpam" INTEGER NULL,
	"isSocialEngineering" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PHONECALLTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHONECALLTAG"(
	"PhoneCallTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "PHYSICALLOCATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSICALLOCATION"(
	"PhysicalLocationID" INTEGER NOT NULL,
	"PhysicalLocationName" TEXT NOT NULL,
	"PhysicalLocationDescription" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PHYSICALLOCATIONASSURANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSICALLOCATIONASSURANCE"(
	"PhysicalLocationAssuranceID" INTEGER NOT NULL
)

;
/****** Object:  Table "PHYSICALLOCATIONCLASSIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSICALLOCATIONCLASSIFICATION"(
	"PhysicalLocationClassificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "PHYSICALLOCATIONCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSICALLOCATIONCONTROL"(
	"PhysicalLocationControlID" INTEGER NOT NULL
)

;
/****** Object:  Table "PHYSICALLOCATIONDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSICALLOCATIONDESCRIPTION"(
	"PhysicalLocationDescriptionID" INTEGER NOT NULL,
	"PhysicalLocationID" INTEGER NOT NULL,
	"PhysicalLocationGUID" TEXT NULL,
	"DescriptionID" INTEGER NULL,
	"DescriptionGUID" TEXT NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PHYSICALLOCATIONRESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSICALLOCATIONRESTRICTION"(
	"PhysicalLocationRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "PHYSICALLOCATIONSECURITYCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSICALLOCATIONSECURITYCONTROL"(
	"PhysicalLocationSecurityControlID" INTEGER NOT NULL
)

;
/****** Object:  Table "PHYSICALLOCATIONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSICALLOCATIONTAG"(
	"PhysicalLocationTagID" INTEGER NOT NULL,
	"PhysicalLocationID" INTEGER NULL,
	"PhysicalLocationGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PHYSIOLOGICALCHARACTERISTIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PHYSIOLOGICALCHARACTERISTIC"(
	"PhysiologicalCharacteristicID" INTEGER NOT NULL
)

;
/****** Object:  Table "PIPEOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PIPEOBJECT"(
	"PipeObjectID" INTEGER NOT NULL
)

;
/****** Object:  Table "PKI"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PKI"(
	"PKIID" INTEGER NOT NULL
)

;
/****** Object:  Table "PLAN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLAN"(
	"PlanID" INTEGER NOT NULL
)

;
/****** Object:  Table "PLATFORM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLATFORM"(
	"PlatformID" INTEGER NOT NULL,
	"PlatformGUID" TEXT NULL,
	"PlatformName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"PlatformDescription" TEXT NULL,
	"structuring_format" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PLATFORMFORCCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLATFORMFORCCE"(
	"CCEPlatformID" INTEGER NOT NULL,
	"CCEID" INTEGER NULL,
	"PlatformID" INTEGER NOT NULL,
	"cce_id" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PLATFORMFORTECHNICALCONTEXT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLATFORMFORTECHNICALCONTEXT"(
	"TechnicalContextPlatformID" INTEGER NOT NULL,
	"TechnicalContextPlatformGUID" TEXT NULL,
	"PlatformID" INTEGER NOT NULL,
	"PlatformGUID" TEXT NULL,
	"TechnicalContextID" INTEGER NOT NULL,
	"TechnicalContextGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PLATFORMMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLATFORMMAPPING"(
	"PlatformMappingID" INTEGER NOT NULL,
	"PlaformRefID" INTEGER NULL,
	"PlatformRefGUID" TEXT NULL,
	"PlatformRelationship" TEXT NULL,
	"PlatformSubjectID" INTEGER NULL,
	"PlatformSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PLATFORMSPECIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLATFORMSPECIFICATION"(
	"PlatformSpecificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "PLATFORMTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLATFORMTAG"(
	"PlatformTagID" INTEGER NOT NULL,
	"PlatformID" INTEGER NULL,
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
/****** Object:  Table "PLUGIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLUGIN"(
	"PluginID" INTEGER NOT NULL,
	"PluginGUID" TEXT NULL,
	"PluginName" TEXT NULL,
	"PluginDescription" TEXT NULL,
	"ModuleID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PLUGINPARAMETER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLUGINPARAMETER"(
	"PluginParameterID" INTEGER NOT NULL,
	"PluginID" INTEGER NOT NULL,
	"ParameterID" INTEGER NOT NULL,
	"ordinal_position" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PLUGINREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLUGINREFERENCE"(
	"PluginReferenceID" INTEGER NOT NULL,
	"PluginID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "PLUGINTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLUGINTAG"(
	"PluginTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "PLUGINVERSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PLUGINVERSION"(
	"PluginVersionID" INTEGER NOT NULL,
	"PluginID" INTEGER NOT NULL,
	"VersionID" INTEGER NOT NULL,
	"PluginVersionDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "POLICY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "POLICY"(
	"PolicyID" INTEGER NOT NULL,
	"PolicyName" TEXT NULL,
	"PolicyDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "POLICYTERM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "POLICYTERM"(
	"PolicyTermID" INTEGER NOT NULL,
	"AcronymID" INTEGER NULL,
	"PolicyTerm" TEXT NOT NULL,
	"PolicyTermDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "POLICYTERMFORPOLICY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "POLICYTERMFORPOLICY"(
	"PolicyTermForPolicyID" INTEGER NOT NULL,
	"PolicyID" INTEGER NOT NULL,
	"PolicyTermID" INTEGER NOT NULL
)

;
/****** Object:  Table "PORT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PORT"(
	"PortID" INTEGER NOT NULL,
	"Port_Value" INTEGER NOT NULL,
	"ProtocolID" INTEGER NULL,
	"DefaultProtocolName" TEXT NULL,
	"DefaultServiceName" TEXT NULL,
	"PortName" TEXT NULL,
	"PortDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PORTFOREXPLOIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PORTFOREXPLOIT"(
	"ExploitPortID" INTEGER NOT NULL,
	"ExploitID" INTEGER NOT NULL,
	"ExploitGUID" TEXT NULL,
	"ExploitPortRelationship" TEXT NULL,
	"PortID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "PORTFORVULNERABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PORTFORVULNERABILITY"(
	"VulnerabilityPortID" INTEGER NOT NULL,
	"VulnerabilityID" INTEGER NOT NULL,
	"VulnerabilityGUID" TEXT NULL,
	"VulnerabilityPortRelationship" TEXT NULL,
	"PortID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "POSSIBLERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "POSSIBLERESTRICTION"(
	"PossibleRestrictionID" INTEGER NOT NULL,
	"RestrictionHint" TEXT NOT NULL
)

;
/****** Object:  Table "POSTALADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "POSTALADDRESS"(
	"PostalAddressID" INTEGER NOT NULL
)

;
/****** Object:  Table "PREVALENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PREVALENCE"(
	"PrevalenceID" INTEGER NOT NULL,
	"PrevalenceName" TEXT NOT NULL,
	"PrevalenceDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PRIORITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRIORITYLEVEL"(
	"PriorityLevelID" INTEGER NOT NULL,
	"PriorityLevelName" TEXT NULL,
	"PriotityCode" TEXT NULL,
	"Sequencing" TEXT NULL,
	"PriorityLevelDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRIVACYNOTIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRIVACYNOTIFICATION"(
	"PrivacyNotificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "PRIVACYRULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRIVACYRULE"(
	"PrivacyRuleID" INTEGER NOT NULL
)

;
/****** Object:  Table "PRIVILEGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRIVILEGE"(
	"PrivilegeID" INTEGER NOT NULL
)

;
/****** Object:  Table "PRIVILEGEESCALATIONPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRIVILEGEESCALATIONPROPERTIES"(
	"PrivilegeEscalationPropertiesID" INTEGER NOT NULL,
	"PrivilegeEscalationPropertiesName" TEXT NULL,
	"PrivilegeEscalationPropertiesDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRIVILEGEESCALATIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRIVILEGEESCALATIONSTRATEGICOBJECTIVE"(
	"PrivilegeEscalationStrategicObjectiveID" INTEGER NOT NULL,
	"PrivilegeEscalationStrategicObjectiveName" TEXT NULL,
	"PrivilegeEscalationStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRIVILEGEESCALATIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRIVILEGEESCALATIONTACTICALOBJECTIVE"(
	"PrivilegeEscalationTacticalObjectiveID" INTEGER NOT NULL,
	"PrivilegeEscalationTacticalObjectiveName" TEXT NULL,
	"PrivilegeEscalationTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRIVILEGESFORROLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRIVILEGESFORROLE"(
	"ID" INTEGER NOT NULL,
	"RoleID" TEXT NULL,
	"Responsible" INTEGER NULL,
	"Accountable" INTEGER NULL,
	"Consulted" INTEGER NULL,
	"Informed" INTEGER NULL
)

;
/****** Object:  Table "PROBINGSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROBINGSTRATEGICOBJECTIVE"(
	"ProbingStrategicObjectiveID" INTEGER NOT NULL,
	"ProbingStrategicObjectiveName" TEXT NULL,
	"ProbingStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROBINGTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROBINGTACTICALOBJECTIVE"(
	"ProbingTacticalObjectiveID" INTEGER NOT NULL,
	"ProbingTacticalObjectiveName" TEXT NULL,
	"ProbingTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROBINGTECHNIQUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROBINGTECHNIQUE"(
	"ProbingTechniqueID" INTEGER NOT NULL,
	"ProbingTechniqueGUID" TEXT NULL,
	"TechniqueID" INTEGER NULL,
	"ProbingTechniqueName" TEXT NULL,
	"ProbingTechniqueDescription" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROBINGTECHNIQUEFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROBINGTECHNIQUEFORATTACKPATTERN"(
	"AttackPatternProbingTechniqueID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"capec_id" TEXT NULL,
	"ProbingTechniqueID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PROCEDURE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROCEDURE"(
	"ProcedureID" INTEGER NOT NULL
)

;
/****** Object:  Table "PROCESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROCESS"(
	"ProcessID" INTEGER NOT NULL
)

;
/****** Object:  Table "PROCESSACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROCESSACTIONNAME"(
	"ProcessActionNameID" INTEGER NOT NULL,
	"ProcessActionNameName" TEXT NOT NULL,
	"ProcessActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PROCESSMEMORYACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROCESSMEMORYACTIONNAME"(
	"ProcessMemoryActionNameID" INTEGER NOT NULL,
	"ProcessMemoryActionNameName" TEXT NOT NULL,
	"ProcessMemoryActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PROCESSORTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROCESSORTYPE"(
	"ProcessorTypeID" INTEGER NOT NULL,
	"ProcessorTypeName" TEXT NOT NULL,
	"ProcessorTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PROCESSORTYPEMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROCESSORTYPEMAPPING"(
	"ProcessorTypeMappingID" INTEGER NOT NULL,
	"ProcessorTypeRefID" INTEGER NOT NULL,
	"ProcessorTypeSubjectID" INTEGER NOT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROCESSORTYPEREGISTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROCESSORTYPEREGISTER"(
	"ProcessorTypeID" INTEGER NOT NULL,
	"RegisterID" INTEGER NOT NULL
)

;
/****** Object:  Table "PROCESSTHREADACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROCESSTHREADACTIONNAME"(
	"ProcessThreadActionNameID" INTEGER NOT NULL,
	"ProcessThreadActionNameName" TEXT NOT NULL,
	"ProcessThreadActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PRODUCT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCT"(
	"ProductID" INTEGER NOT NULL,
	"ProductGUID" TEXT NULL,
	"ProductName" TEXT NULL,
	"ProductVendor" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"CPEName" TEXT NULL,
	"ProductEdition" TEXT NULL,
	"ProductUpdate" TEXT NULL,
	"ProductVersion" TEXT NULL,
	"CPEID" INTEGER NULL,
	"ProductLanguage" TEXT NULL,
	"LocaleID" INTEGER NULL,
	"DeviceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ProductDescription" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTCATEGORY"(
	"ProductCategoryID" INTEGER NOT NULL,
	"ProductCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"ProductCategoryName" TEXT NULL,
	"ProductCategoryShortName" TEXT NULL,
	"ProductCategoryDescription" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTCATEGORYFORPRODUCT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTCATEGORYFORPRODUCT"(
	"ProductCategoryForProductID" INTEGER NOT NULL,
	"ProductID" INTEGER NOT NULL,
	"ProductGUID" TEXT NULL,
	"ProductCategoryID" INTEGER NOT NULL,
	"ProductCategoryGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTEXPLOIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTEXPLOIT"(
	"ProductExploitID" INTEGER NOT NULL,
	"ProductID" INTEGER NULL,
	"ProductGUID" TEXT NULL,
	"ExploitID" INTEGER NULL,
	"ExploitGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTFILE"(
	"ProductFileID" INTEGER NOT NULL,
	"ProductID" INTEGER NULL,
	"ProductFileRelationship" TEXT NULL,
	"ProductFileDescription" TEXT NULL,
	"FileID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTFILELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTFILELIST"(
	"ProductFileListID" INTEGER NOT NULL,
	"ProductID" INTEGER NULL,
	"ProductGUID" TEXT NULL,
	"ProductFileListRelationship" TEXT NULL,
	"ProductFileListDescription" TEXT NULL,
	"FileListID" INTEGER NULL,
	"FileListGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTMAPPING"(
	"ProductMappingID" INTEGER NOT NULL,
	"ProductRefID" INTEGER NULL,
	"ProductRefGUID" TEXT NULL,
	"ProductRelationship" TEXT NULL,
	"ProductMappingDescription" TEXT NULL,
	"ProductSubjectID" INTEGER NULL,
	"ProductSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTPATCH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTPATCH"(
	"ProductPatchID" INTEGER NOT NULL,
	"ProductID" INTEGER NULL,
	"ProductGUID" TEXT NULL,
	"ProductPatchRelationship" TEXT NULL,
	"ProductPatchDescription" TEXT NULL,
	"PatchID" INTEGER NULL,
	"PatchGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTPLATFORM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTPLATFORM"(
	"ProductPlaformID" INTEGER NOT NULL,
	"ProductID" INTEGER NULL,
	"ProductGUID" TEXT NULL,
	"ProductPlatformRelationship" TEXT NULL,
	"PlatformID" INTEGER NULL,
	"PlatformGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromdate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTPORT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTPORT"(
	"ProductPortID" INTEGER NOT NULL,
	"ProductID" INTEGER NULL,
	"ProductGUID" TEXT NULL,
	"ProductPortRelationship" TEXT NULL,
	"PortID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "PRODUCTTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PRODUCTTAG"(
	"ProductTagID" INTEGER NOT NULL,
	"ProductID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PROJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECT"(
	"ProjectID" INTEGER NOT NULL,
	"ProjectGUID" TEXT NULL,
	"ProjectName" TEXT NOT NULL,
	"ProjectDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ExpectedCompletionDate" TEXT NULL,
	"DueDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ImportanceID" INTEGER NULL
)

;
/****** Object:  Table "PROJECTDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTDESCRIPTION"(
	"ProjectDescriptionID" INTEGER NOT NULL,
	"ProjectID" INTEGER NULL,
	"ProjectGUID" TEXT NULL,
	"DescriptionID" INTEGER NULL,
	"DescriptionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROJECTFINDING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTFINDING"(
	"ProjectFindingID" INTEGER NOT NULL,
	"ProjectID" INTEGER NULL,
	"ProjectGUID" TEXT NULL,
	"FindingID" INTEGER NULL,
	"FindingGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PROJECTFORAPPLICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTFORAPPLICATION"(
	"ProjectApplicationID" INTEGER NOT NULL,
	"ProjectID" INTEGER NOT NULL,
	"ProjectGUID" TEXT NULL,
	"ApplicationID" INTEGER NOT NULL,
	"ApplicationGUID" TEXT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"ProjectDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PROJECTMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTMAPPING"(
	"ProjectMappingID" INTEGER NOT NULL,
	"ProjectRefID" INTEGER NULL,
	"ProjectRefGUID" TEXT NULL,
	"ProjectRelationship" TEXT NULL,
	"ProjectMappingDescription" TEXT NULL,
	"ProjectSubjectID" INTEGER NULL,
	"ProjectSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROJECTMETHODOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTMETHODOLOGY"(
	"ProjectMethodologyID" INTEGER NOT NULL,
	"ProjectID" INTEGER NOT NULL,
	"ProjectGUID" TEXT NULL,
	"MethodologyID" INTEGER NOT NULL,
	"MethodologyGUID" TEXT NULL,
	"PersonID" INTEGER NULL,
	"PersonGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ProjectMethodologyDescription" TEXT NOT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PROJECTPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTPERSON"(
	"ProjectPersonID" INTEGER NOT NULL,
	"ProjectID" INTEGER NOT NULL,
	"ProjectGUID" TEXT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonGUID" TEXT NULL,
	"ProjectPersonRole" TEXT NULL,
	"ProjectPersonDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PROJECTTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTTAG"(
	"ProjectTagID" INTEGER NOT NULL,
	"ProjectID" INTEGER NULL,
	"ProjectGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROJECTTASK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTTASK"(
	"ProjectTaskID" INTEGER NOT NULL,
	"ProjectID" INTEGER NOT NULL,
	"ProjectGUID" TEXT NULL,
	"TaskID" INTEGER NOT NULL,
	"TaskGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ProjectTaskName" TEXT NULL,
	"ProjectTaskDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "PROJECTTASKFINDING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTTASKFINDING"(
	"ProjectTaskFindingID" INTEGER NOT NULL,
	"ProjectTaskID" INTEGER NULL,
	"ProjectTaskGUID" TEXT NULL,
	"FindingID" INTEGER NULL,
	"FindingGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROJECTTASKPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTTASKPERSON"(
	"ProjectTaskPersonID" INTEGER NOT NULL,
	"ProjectTaskID" INTEGER NOT NULL,
	"ProjectTaskGUID" TEXT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ProjectTaskPersonRole" TEXT NULL,
	"ProjectTaskDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROJECTTECHNIQUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROJECTTECHNIQUE"(
	"ProjectTechniqueID" INTEGER NOT NULL
)

;
/****** Object:  Table "PROPERTYTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROPERTYTYPE"(
	"PropertyTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "PROTOCOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROTOCOL"(
	"ProtocolID" INTEGER NOT NULL,
	"ProtocolAbbreviation" TEXT NULL,
	"ProtocolName" TEXT NOT NULL,
	"ProtocolDescription" TEXT NULL,
	"ProtocolRFC" TEXT NULL,
	"ProtocolBAF" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"OSILayerID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "PROTOCOLCOMMAND"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROTOCOLCOMMAND"(
	"ProtocolCommandID" INTEGER NOT NULL,
	"ProtocolID" INTEGER NULL,
	"CommandID" INTEGER NULL,
	"KnownVulnerable" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROTOCOLFORPROTOCOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROTOCOLFORPROTOCOL"(
	"ProtocolRelationshipID" INTEGER NOT NULL,
	"ProtocolRefID" INTEGER NOT NULL,
	"ProtocolRelationshipName" TEXT NULL,
	"ProtocolSubjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROTOCOLHEADER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROTOCOLHEADER"(
	"ProtocolHeaderID" INTEGER NOT NULL,
	"ProtocolHeaderGUID" TEXT NULL,
	"Protocol_Field_Name" TEXT NULL,
	"Protocol_Field_Description" TEXT NULL,
	"Protocol_Operation_Code" TEXT NULL,
	"Protocol_Data" TEXT NULL,
	"Protocol_Flag_Value" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROTOCOLREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROTOCOLREFERENCE"(
	"ProtocolReferenceID" INTEGER NOT NULL,
	"ProtocolID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROVIDER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROVIDER"(
	"ProviderID" INTEGER NOT NULL,
	"ProviderGUID" TEXT NULL,
	"ProviderName" TEXT NULL,
	"PluginReference" TEXT NULL,
	"ServiceCategoryID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "PROVIDERSFORACCOUNT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "PROVIDERSFORACCOUNT"(
	"ProviderAccountID" INTEGER NOT NULL,
	"ProviderID" INTEGER NULL,
	"AccountID" INTEGER NULL,
	"ValidUntil" TEXT NULL
)

;
/****** Object:  Table "RACIMATRIX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RACIMATRIX"(
	"RACIMatrixID" INTEGER NOT NULL,
	"TaskType" TEXT NULL,
	"TaskID" TEXT NULL,
	"RACIResponsability" TEXT NULL,
	"UserID" TEXT NULL,
	"AccountID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RACITASK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RACITASK"(
	"RACITaskID" INTEGER NOT NULL,
	"TaskType" TEXT NULL,
	"RACIResponsability" TEXT NULL,
	"UserID" TEXT NULL,
	"AccountID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RATEFILTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RATEFILTER"(
	"RateFilterID" INTEGER NOT NULL,
	"RateFilterContent" TEXT NULL,
	"RateFilterDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RAWARTIFACT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RAWARTIFACT"(
	"RawArtifactID" INTEGER NOT NULL,
	"RawArtifactGUID" TEXT NULL,
	"byte_order" TEXT NULL,
	"is_encrypted" INTEGER NULL,
	"is_compressed" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"SourceID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RAWARTIFACTDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RAWARTIFACTDESCRIPTION"(
	"RawArtifactDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "RAWARTIFACTTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RAWARTIFACTTAG"(
	"RawArtifactTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "REASON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REASON"(
	"ReasonID" INTEGER NOT NULL,
	"ReasonGUID" TEXT NULL,
	"ReasonName" TEXT NULL,
	"ReasonDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "RECOMMENDATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RECOMMENDATION"(
	"RecommendationID" INTEGER NOT NULL,
	"RecommendationGUID" TEXT NULL,
	"RecommendationVocabularyID" TEXT NULL,
	"RecommendationName" TEXT NULL,
	"RecommendationLevel" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"RecommendationDescription" TEXT NULL,
	"RecommendationRationale" TEXT NULL,
	"RemediationProcedure" TEXT NULL,
	"RecommendationImpact" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"StatusID" INTEGER NULL,
	"ScoringStatusID" INTEGER NULL,
	"LocaleID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RECOMMENDATIONAUDITPROCEDURE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RECOMMENDATIONAUDITPROCEDURE"(
	"RecommendationAuditProcedureID" INTEGER NOT NULL,
	"RecommendationID" INTEGER NOT NULL,
	"AuditProcedureID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"RecommendationAuditProcedureName" TEXT NULL,
	"RecommendationAuditProcedureDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "RECOMMENDATIONCCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RECOMMENDATIONCCE"(
	"RecommendationCCEID" INTEGER NOT NULL,
	"RecommendationID" INTEGER NOT NULL,
	"RecommendationGUID" TEXT NULL,
	"CCEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RECOMMENDATIONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RECOMMENDATIONTAG"(
	"RecommendationTagID" INTEGER NOT NULL,
	"RecommendationID" INTEGER NOT NULL,
	"RecommendationGUID" TEXT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RECOMMENDATIONTIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RECOMMENDATIONTIP"(
	"RecommendationTipID" INTEGER NOT NULL,
	"RecommendationTypeGUID" TEXT NULL,
	"RecommendationID" INTEGER NULL,
	"RecommendationGUID" TEXT NULL,
	"TipID" INTEGER NULL,
	"TipGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "REFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REFERENCE"(
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"ReferenceSourceID" TEXT NULL,
	"Source" TEXT NULL,
	"SourceTrustLevelID" INTEGER NULL,
	"SourceTrustReasonID" INTEGER NULL,
	"ReferenceTitle" TEXT NULL,
	"ReferenceDescription" TEXT NULL,
	"Type" TEXT NULL,
	"ReferenceCategoryID" INTEGER NULL,
	"ReferenceURL" TEXT NULL,
	"ReferenceFilePath" TEXT NULL,
	"lang" TEXT NULL,
	"LocaleID" INTEGER NULL,
	"notes" TEXT NULL,
	"ReferenceVersion" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"Reference_Publication" TEXT NULL,
	"Reference_Edition" TEXT NULL,
	"Reference_PubDate" TEXT NULL,
	"Reference_Publisher" TEXT NULL,
	"ReferenceISBN" TEXT NULL,
	"Reference_Date" TEXT NULL
)

;
/****** Object:  Table "REFERENCEAUTHOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REFERENCEAUTHOR"(
	"ReferenceAuthorID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"AuthorID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "REFERENCECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REFERENCECATEGORY"(
	"ReferenceCategoryID" INTEGER NOT NULL,
	"ReferenceCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NOT NULL,
	"ReferenceCategoryName" TEXT NULL,
	"ReferenceCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "REFERENCECATEGORYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REFERENCECATEGORYTAG"(
	"ReferenceCategoryTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "REFERENCECHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REFERENCECHANGERECORD"(
	"ReferenceChangeRecordID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"ChangeRecordID" INTEGER NOT NULL,
	"ChangeRecordGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REFERENCEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REFERENCEDESCRIPTION"(
	"ReferenceDescriptionID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REFERENCEMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REFERENCEMAPPING"(
	"ReferenceMappingID" INTEGER NOT NULL,
	"ReferenceRefID" INTEGER NULL,
	"RelationShipText" TEXT NULL,
	"ReferenceSubjectID" INTEGER NULL,
	"ReferenceMappingDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REFERENCETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REFERENCETAG"(
	"ReferenceTagID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REGEX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGEX"(
	"RegexID" INTEGER NOT NULL,
	"RegularExpression" TEXT NULL,
	"RegexDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "REGEXCAPTUREFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGEXCAPTUREFUNCTION"(
	"RegexCaptureFunctionID" INTEGER NOT NULL,
	"Regex" TEXT NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL
)

;
/****** Object:  Table "REGEXLANGUAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGEXLANGUAGE"(
	"RegexLanguageID" INTEGER NOT NULL,
	"RegexID" INTEGER NOT NULL,
	"LanguageID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "REGEXREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGEXREFERENCE"(
	"RegexReferenceID" INTEGER NOT NULL,
	"RegexID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "REGISTER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTER"(
	"RegisterID" INTEGER NOT NULL,
	"RegisterName" TEXT NOT NULL,
	"RegisterDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "REGISTRYACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYACTIONNAME"(
	"RegistryActionNameID" INTEGER NOT NULL,
	"RegistryActionNameName" TEXT NOT NULL,
	"RegistryActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "REGISTRYDATATYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYDATATYPE"(
	"RegistryDatatypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "REGISTRYDATATYPEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYDATATYPEREFERENCE"(
	"RegistryDatatypeReferenceID" INTEGER NOT NULL,
	"RegistryDatatypeID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REGISTRYDATATYPESENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYDATATYPESENUM"(
	"RegistryDatatypesEnumID" INTEGER NOT NULL,
	"RegistryDatatypeName" TEXT NOT NULL,
	"RegistryDatatypeDescription" TEXT NULL,
	"RegistryDatatypeReference" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REGISTRYHIVEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYHIVEENUM"(
	"RegistryHiveEnumID" INTEGER NOT NULL,
	"RegistryHiveName" TEXT NOT NULL,
	"RegistryHiveDescription" TEXT NULL,
	"RegistryHiveReference" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REGISTRYSUBKEYS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYSUBKEYS"(
	"RegistrySubkeysID" INTEGER NOT NULL
)

;
/****** Object:  Table "REGISTRYSUBKEYSKEYS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYSUBKEYSKEYS"(
	"RegistrySubkeysKeysID" INTEGER NOT NULL,
	"RegistrySubkeysID" INTEGER NOT NULL,
	"WindowsRegistryKeyObjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "REGISTRYVALUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYVALUE"(
	"RegistryValueID" INTEGER NOT NULL,
	"Name" TEXT NULL,
	"Data" TEXT NULL,
	"RegistryDatatypeID" INTEGER NULL,
	"ByteRunsID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "REGISTRYVALUES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYVALUES"(
	"RegistryValuesID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REGISTRYVALUESREGISTRYVALUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGISTRYVALUESREGISTRYVALUE"(
	"RegistryValuesRegistryValueID" INTEGER NOT NULL,
	"RegistryValuesID" INTEGER NOT NULL,
	"RegistryValueID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "REGULAREXPRESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGULAREXPRESSION"(
	"RegularExpressionID" INTEGER NOT NULL,
	"RegexID" INTEGER NULL
)

;
/****** Object:  Table "REGULATORYRISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REGULATORYRISK"(
	"RegulatoryRiskID" INTEGER NOT NULL,
	"RegulatoryRiskGUID" TEXT NULL,
	"RiskDescription" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RELATIONSHIPTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RELATIONSHIPTYPE"(
	"RelationshipTypeID" INTEGER NOT NULL,
	"RelationshipTypeTerm" TEXT NULL,
	"RelationshipTypeDomain" TEXT NULL,
	"RelationshipTypeRange" TEXT NULL,
	"RelationshipTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "RELIABILITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RELIABILITY"(
	"ReliabilityID" INTEGER NOT NULL,
	"ReliabilityGUID" TEXT NULL,
	"ReliabilityName" TEXT NULL,
	"ReliabilityDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "RELIABILITYREASON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RELIABILITYREASON"(
	"ReliabilityReasonID" INTEGER NOT NULL,
	"ReliabilityReasonGUID" TEXT NULL,
	"ReasonID" INTEGER NULL,
	"ReasonGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "REMOTEMACHINEMANIPULATIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REMOTEMACHINEMANIPULATIONSTRATEGICOBJECTIVE"(
	"RemoteMachineManipulationStrategicObjectiveID" INTEGER NOT NULL,
	"RemoteMachineManipulationStrategicObjectiveName" TEXT NULL,
	"RemoteMachineManipulationStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REMOTEMACHINEMANIPULATIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REMOTEMACHINEMANIPULATIONTACTICALOBJECTIVE"(
	"RemoteMachineManipulationTacticalObjectiveID" INTEGER NOT NULL,
	"RemoteMachineManipulationTacticalObjectiveName" TEXT NULL,
	"RemoteMachineManipulationTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REPORT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPORT"(
	"ReportID" INTEGER NOT NULL,
	"ReportGUID" TEXT NULL,
	"ReportContent" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "REPORTFORREPORTS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPORTFORREPORTS"(
	"ReportsID" INTEGER NOT NULL,
	"ReportID" INTEGER NOT NULL
)

;
/****** Object:  Table "REPORTREQUEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPORTREQUEST"(
	"ReportRequestID" INTEGER NOT NULL,
	"ARFReportRequestID" TEXT NOT NULL,
	"ReportRequestContent" TEXT NULL,
	"ReferenceID" INTEGER NULL
)

;
/****** Object:  Table "REPORTREQUESTFORREPORTREQUESTS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPORTREQUESTFORREPORTREQUESTS"(
	"ReportRequestsID" INTEGER NOT NULL,
	"ReportRequestID" INTEGER NOT NULL
)

;
/****** Object:  Table "REPORTREQUESTS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPORTREQUESTS"(
	"ReportRequestsID" INTEGER NOT NULL
)

;
/****** Object:  Table "REPORTS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPORTS"(
	"ReportsID" INTEGER NOT NULL
)

;
/****** Object:  Table "REPOSITORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPOSITORY"(
	"RepositoryID" INTEGER NOT NULL,
	"RepositoryGUID" TEXT NULL,
	"RepositoryName" TEXT NULL,
	"RepositoryDescription" TEXT NULL,
	"RepositoryURL" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "REPOSITORYRESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPOSITORYRESTRICTION"(
	"RepositoryRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "REPUTATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REPUTATION"(
	"ReputationID" INTEGER NOT NULL,
	"ReputationGUID" TEXT NULL,
	"ReputationTitle" TEXT NULL,
	"ReputationDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REQUIREMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REQUIREMENT"(
	"RequirementID" INTEGER NOT NULL,
	"RequirementGUID" TEXT NULL,
	"RequirementTitle" TEXT NULL,
	"RequirementDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "REQUIREMENTCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REQUIREMENTCATEGORY"(
	"RequirementCategoryID" INTEGER NOT NULL,
	"RequirementID" INTEGER NULL,
	"CategoryID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "REQUIREMENTDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REQUIREMENTDESCRIPTION"(
	"RequirementDescriptionID" INTEGER NOT NULL,
	"RequirementID" INTEGER NULL,
	"DescriptionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "REQUIREMENTMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "REQUIREMENTMAPPING"(
	"RequirementMappingID" INTEGER NOT NULL,
	"RequirementRefID" INTEGER NULL,
	"RequirementRefGUID" TEXT NULL,
	"RequirementSubjectID" INTEGER NULL,
	"RequirementSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "RESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RESTRICTION"(
	"RestrictionID" INTEGER NOT NULL,
	"OperationEnumerationValue" TEXT NOT NULL,
	"VariableValue" TEXT NOT NULL
)

;
/****** Object:  Table "RESULTENUMERATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RESULTENUMERATION"(
	"ResultEnumerationID" INTEGER NOT NULL,
	"ResultEnumerationValue" TEXT NOT NULL,
	"ResultEnumerationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "RISKRATING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RISKRATING"(
	"RiskRatingID" INTEGER NOT NULL,
	"RiskRatingGUID" TEXT NULL,
	"RiskRatingName" TEXT NULL,
	"RiskRatingDescription" TEXT NULL,
	"MethodologyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ROLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ROLE"(
	"RoleID" INTEGER NOT NULL,
	"RoleGUID" TEXT NULL,
	"RoleName" TEXT NULL,
	"RoleDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ROPCHAIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ROPCHAIN"(
	"ROPChainID" INTEGER NOT NULL,
	"ROPChainName" TEXT NOT NULL,
	"ROPChainDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ROPCHAININSTRUCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ROPCHAININSTRUCTION"(
	"ROPChainID" INTEGER NOT NULL,
	"InstructionID" INTEGER NOT NULL
)

;
/****** Object:  Table "ROPCHAINREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ROPCHAINREFERENCE"(
	"ROPChainID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ROPGADGET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ROPGADGET"(
	"ROPGadgetID" INTEGER NOT NULL,
	"ROPGadgetGUID" TEXT NULL,
	"ROPGadgetName" TEXT NULL,
	"ROPGadgetDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ReliabilityID" INTEGER NULL
)

;
/****** Object:  Table "ROPGADGETFORROPCHAIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ROPGADGETFORROPCHAIN"(
	"ROPChainID" INTEGER NOT NULL,
	"ROPGadgetID" INTEGER NOT NULL,
	"ROPGadgetOrder" INTEGER NOT NULL
)

;
/****** Object:  Table "ROPGADGETINSTRUCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ROPGADGETINSTRUCTION"(
	"ROGGadgetID" INTEGER NOT NULL,
	"InstructionID" INTEGER NOT NULL,
	"InstructionOrder" INTEGER NOT NULL
)

;
/****** Object:  Table "ROPGADGETTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ROPGADGETTAG"(
	"ROPGadgetTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "RSAPUBLICKEY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RSAPUBLICKEY"(
	"RSAPublicKeyID" INTEGER NOT NULL,
	"RSAPublicKeyGUID" TEXT NULL,
	"Modulus" TEXT NOT NULL,
	"Exponent" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL,
	"CreationDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "RSAPUBLICKEYACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RSAPUBLICKEYACCESSRECORD"(
	"RSAPlublicKeyAccessRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "RULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RULE"(
	"RuleID" INTEGER NOT NULL,
	"RuleGUID" TEXT NULL,
	"RuleTitle" TEXT NULL,
	"RuleVersion" INTEGER NULL,
	"RuleDescription" TEXT NULL,
	"RuleContent" TEXT NULL,
	"RuleVocabularyID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RULECATEGORIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RULECATEGORIES"(
	"RuleCategoriesID" INTEGER NOT NULL,
	"RuleID" INTEGER NULL,
	"RuleCategoryID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RULECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RULECATEGORY"(
	"RuleCategoryID" INTEGER NOT NULL,
	"CategoryID" INTEGER NULL,
	"RuleCategoryName" TEXT NULL,
	"RuleCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RULEPRODUCT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RULEPRODUCT"(
	"RuleProductID" INTEGER NOT NULL,
	"RuleID" INTEGER NULL,
	"RuleProductRelationship" TEXT NULL,
	"ProductID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RULEPROTOCOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RULEPROTOCOL"(
	"RuleProtocolID" INTEGER NOT NULL,
	"RuleID" INTEGER NULL,
	"ProtocolID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "RULEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "RULEREFERENCE"(
	"RuleReferenceID" INTEGER NOT NULL,
	"RuleID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SCENARIO"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCENARIO"(
	"ScenarioID" INTEGER NOT NULL,
	"ScenarioName" TEXT NOT NULL,
	"ScenarioDescription" TEXT NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SCENARIOFOROWASPTOP10"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCENARIOFOROWASPTOP10"(
	"OWASPTOP10ScenarioID" INTEGER NOT NULL,
	"OWASPTOP10ID" INTEGER NOT NULL,
	"ScenarioID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "SCHEDULE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCHEDULE"(
	"ScheduleID" INTEGER NOT NULL,
	"ScheduleGUID" TEXT NULL
)

;
/****** Object:  Table "SCHEMA"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCHEMA"(
	"SchemaID" INTEGER NOT NULL
)

;
/****** Object:  Table "SCORINGFORMULA"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCORINGFORMULA"(
	"ScoringFormulaID" INTEGER NOT NULL,
	"ScoringFormulaName" TEXT NOT NULL,
	"ScoringFormulaAbbreviation" TEXT NULL,
	"ScoringFormulaDescription" TEXT NULL,
	"ScoringFormulaIndividualScore" TEXT NULL,
	"ScoringFormulaHostScore" TEXT NULL,
	"ScoringFormulaNotes" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SCORINGSTATUS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCORINGSTATUS"(
	"ScoringStatusID" INTEGER NOT NULL,
	"ScoringStatusName" TEXT NULL,
	"ScoringStatusValue" TEXT NULL,
	"ScoringStatusDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SCORINGSYSTEM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCORINGSYSTEM"(
	"ScoringSystemID" INTEGER NOT NULL,
	"ScoringSystemName" TEXT NOT NULL,
	"ScoringSystemDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SCORINGSYSTEMDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCORINGSYSTEMDESCRIPTION"(
	"ScoringSystemDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "SCORINGSYSTEMFORMULAS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCORINGSYSTEMFORMULAS"(
	"ScoringSystemID" INTEGER NOT NULL,
	"ScoringFormulaID" INTEGER NOT NULL
)

;
/****** Object:  Table "SCORINGSYSTEMREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCORINGSYSTEMREFERENCE"(
	"ScoringSystemID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "SCORINGSYSTEMTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCORINGSYSTEMTAG"(
	"ScoringSystemTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "SCRIPT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCRIPT"(
	"ScriptID" INTEGER NOT NULL,
	"CommandsID" INTEGER NOT NULL,
	"CommandID" INTEGER NOT NULL,
	"CommandArgumentValue" TEXT NULL,
	"ScriptName" TEXT NULL,
	"ScriptDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SCRIPTDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCRIPTDESCRIPTION"(
	"ScriptDescriptionID" INTEGER NOT NULL,
	"ScriptID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SCRIPTTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCRIPTTAG"(
	"ScriptTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "SCRIPTVERSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SCRIPTVERSION"(
	"ScriptVersionID" INTEGER NOT NULL,
	"ScriptID" INTEGER NOT NULL,
	"VersionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECONDARYOPERATIONPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECONDARYOPERATIONPROPERTIES"(
	"SecondaryOperationPropertiesID" INTEGER NOT NULL,
	"SecondaryOperationPropertiesName" TEXT NULL,
	"SecondaryOperationPropertiesDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECONDARYOPERATIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECONDARYOPERATIONSTRATEGICOBJECTIVE"(
	"SecondaryOperationStrategicObjectiveID" INTEGER NOT NULL,
	"SecondaryOperationStrategicObjectiveName" TEXT NULL,
	"SecondaryOperationStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECONDARYOPERATIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECONDARYOPERATIONTACTICALOBJECTIVE"(
	"SecondaryOperationTacticalObjectiveID" INTEGER NOT NULL,
	"SecondaryOperationTacticalObjectiveName" TEXT NULL,
	"SecondaryOperationTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "SECTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECTION"(
	"SectionID" INTEGER NOT NULL,
	"SectionName" TEXT NULL,
	"SectionDescription" TEXT NULL,
	"SectionValue" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromdate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECTIONDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECTIONDESCRIPTION"(
	"SectionDescriptionID" INTEGER NOT NULL,
	"SectionID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SECTIONREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECTIONREFERENCE"(
	"SectionReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECTIONTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECTIONTAG"(
	"SectionTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYATTRIBUTE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYATTRIBUTE"(
	"SecurityAttributeID" INTEGER NOT NULL,
	"SecurityAttributeCategoryID" INTEGER NOT NULL,
	"SecurityAttributeName" TEXT NOT NULL,
	"data_disclosure" TEXT NULL,
	"SecurityAttributeStateID" INTEGER NULL,
	"notes" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"durationvalue" INTEGER NULL,
	"durationunit" TEXT NULL,
	"IncidentID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYATTRIBUTECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYATTRIBUTECATEGORY"(
	"SecurityAttributeCategoryID" INTEGER NOT NULL,
	"SecurityAttributeCategoryName" TEXT NOT NULL,
	"SecurityAttributeCategoryDescription" TEXT NULL
)

;
/****** Object:  Table "SECURITYATTRIBUTESTATE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYATTRIBUTESTATE"(
	"SecurityAttributeStateID" INTEGER NOT NULL,
	"SecurityAttributeCategoryID" INTEGER NOT NULL,
	"SecurityAttributeStateName" TEXT NOT NULL,
	"SecurityAttributeStateDescription" TEXT NULL
)

;
/****** Object:  Table "SECURITYATTRIBUTEVARIETY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYATTRIBUTEVARIETY"(
	"SecurityAttributeVarietyID" INTEGER NOT NULL,
	"SecurityAttributeCategoryID" INTEGER NOT NULL,
	"SecurityAttributeVarietyName" TEXT NOT NULL,
	"SecurityAttributeVarietyDescription" TEXT NULL
)

;
/****** Object:  Table "SECURITYCHANGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCHANGE"(
	"SecurityChangeID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYCOMPROMISEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCOMPROMISEENUM"(
	"SecurityCompromiseEnumID" INTEGER NOT NULL,
	"SecurityCompromiseEnumName" TEXT NULL,
	"SecurityCompromiseEnumDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "SECURITYCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROL"(
	"SecurityControlID" INTEGER NOT NULL,
	"SecurityControlGUID" TEXT NULL,
	"ControlID" INTEGER NULL,
	"SecurityControlName" TEXT NOT NULL,
	"SecurityControlAbbrevation" TEXT NULL,
	"SecurityControlDescription" TEXT NULL,
	"BaselineImpact" TEXT NULL,
	"StatementDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"SecurityControlVocabularyID" TEXT NULL,
	"SecurityControlFamilyID" INTEGER NULL,
	"SecurityControlParentID" INTEGER NULL,
	"SecurityControlTypeID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ReliabilityID" INTEGER NULL
)

;
/****** Object:  Table "SECURITYCONTROLCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLCHANGERECORD"(
	"SecurityControlChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYCONTROLDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLDESCRIPTION"(
	"SecurityControlDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYCONTROLENVIRONMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLENVIRONMENT"(
	"SecurityControlEnvironmentID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYCONTROLFAMILY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLFAMILY"(
	"SecurityControlFamilyID" INTEGER NOT NULL,
	"SecurityControlFamilyName" TEXT NOT NULL,
	"SecurityControlFamilyDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYCONTROLFAMILYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLFAMILYTAG"(
	"SecurityControlFamilyTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYCONTROLFORHUMANRISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLFORHUMANRISK"(
	"HumanRiskSecurityControlID" INTEGER NOT NULL,
	"HumanRiskID" INTEGER NOT NULL,
	"SecurityControlID" INTEGER NOT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "SECURITYCONTROLMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLMAPPING"(
	"SecurityControlMappingID" INTEGER NOT NULL,
	"SecurityControlRefID" INTEGER NOT NULL,
	"SecurityControlRefGUID" TEXT NULL,
	"SecurityControlRelationship" TEXT NULL,
	"SecurityControlMappingDescription" TEXT NULL,
	"SecurityControlSubjectID" INTEGER NOT NULL,
	"SecurityControlSubjectGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "SECURITYCONTROLPRIORITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLPRIORITY"(
	"SecurityControlPriorityID" INTEGER NOT NULL,
	"SecurityControlID" INTEGER NULL,
	"PriorityLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYCONTROLREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLREFERENCE"(
	"SecurityControlReferenceID" INTEGER NOT NULL,
	"SecurityControlID" INTEGER NULL,
	"SecurityControlGUID" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYCONTROLSTRENGTH"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLSTRENGTH"(
	"SecurityControlStrenghtID" INTEGER NOT NULL,
	"SecurityControlID" INTEGER NOT NULL,
	"ControlStrengthID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYCONTROLTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLTAG"(
	"SecurityControlTagID" INTEGER NOT NULL,
	"SecurityControlID" INTEGER NULL,
	"SecurityControlGUID" TEXT NULL,
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
/****** Object:  Table "SECURITYCONTROLTEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLTEST"(
	"SecurityControlTestID" INTEGER NOT NULL,
	"SecurityControlTestGUID" TEXT NULL,
	"SecurityControlID" INTEGER NULL,
	"SecurityControlGUID" TEXT NULL,
	"TestID" INTEGER NULL,
	"TestGUID" TEXT NULL,
	"TestVocabularyID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYCONTROLTOOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLTOOL"(
	"SecurityControlToolID" INTEGER NOT NULL,
	"SecurityControlID" INTEGER NOT NULL,
	"SecuriyControlGUID" TEXT NULL,
	"RelationshipName" TEXT NULL,
	"ToolInformationID" INTEGER NOT NULL,
	"ToolInformationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYCONTROLTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLTYPE"(
	"SecurityControlTypeID" INTEGER NOT NULL,
	"SecurityControlTypeName" TEXT NULL,
	"SecurityControlTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYCONTROLTYPETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYCONTROLTYPETAG"(
	"SecurityControlTypeTagID" INTEGER NOT NULL,
	"SecurityControlTypeID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYDEGRADATIONPROPERTIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYDEGRADATIONPROPERTIES"(
	"SecurityDegradationPropertiesID" INTEGER NOT NULL,
	"SecurityDegradationPropertiesName" TEXT NULL,
	"SecurityDegradationPropertiesDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYDEGRADATIONSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYDEGRADATIONSTRATEGICOBJECTIVE"(
	"SecurityDegradationStrategicObjectiveID" INTEGER NOT NULL,
	"SecurityDegradationStrategicObjectiveName" TEXT NULL,
	"SecurityDegradationStrategicObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYDEGRADATIONTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYDEGRADATIONTACTICALOBJECTIVE"(
	"SecurityDegradationTacticalObjectiveID" INTEGER NOT NULL,
	"SecurityDegradationTacticalObjectiveName" TEXT NULL,
	"SecurityDegradationTacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "SECURITYDOMAIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYDOMAIN"(
	"SecurityDomainID" INTEGER NOT NULL,
	"SecurityDomainGUID" TEXT NULL,
	"SecurityDomainName" TEXT NULL,
	"SecurityDomainDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYDOMAINMATURITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYDOMAINMATURITY"(
	"SecurityDomainMaturityID" INTEGER NOT NULL,
	"SecurityDomainID" INTEGER NULL,
	"SecurityDomainGUID" TEXT NULL,
	"MaturityLevelID" INTEGER NULL,
	"MaturityLevelGUID" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"OrganizationalUnitID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"SecurityDomainMaturityDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYDOMAINOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYDOMAINOBJECTIVE"(
	"SecurityDomainObjectiveID" INTEGER NOT NULL,
	"SecurityDomainID" INTEGER NULL,
	"SecurityDomainGUID" TEXT NULL,
	"ObjectiveID" INTEGER NULL,
	"ObjectiveGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYDOMAINPROCESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYDOMAINPROCESS"(
	"SecurityDomainProcessID" INTEGER NOT NULL,
	"SecurityDomainID" INTEGER NOT NULL,
	"SecurityDomainGUID" TEXT NULL,
	"SecurityProcessID" INTEGER NOT NULL,
	"SecurityProcessGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYDOMAINTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYDOMAINTAG"(
	"SecurityDomainTagID" INTEGER NOT NULL,
	"SecurityDomainID" INTEGER NULL,
	"SecurityDomainGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYEVALUATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYEVALUATION"(
	"SecurityEvaluationID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYLABEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYLABEL"(
	"SecurityLabelID" INTEGER NOT NULL,
	"LabelID" INTEGER NULL,
	"SecurityLabelName" TEXT NULL,
	"SecurityLabelDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYLABELREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYLABELREFERENCE"(
	"SecurityLabelReferenceID" INTEGER NOT NULL,
	"SecurityLabelID" INTEGER NOT NULL,
	"SecurityLabelGUID" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYMARKING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYMARKING"(
	"SecurityMarkingID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYMETRIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYMETRIC"(
	"SecurityMetricID" INTEGER NOT NULL,
	"SecurityMetricGUID" TEXT NULL,
	"SecurityMetricName" TEXT NULL,
	"SecurityMetricDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYMETRICDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYMETRICDESCRIPTION"(
	"SecurityMetricDescriptionID" INTEGER NOT NULL,
	"SecurityMetricID" INTEGER NULL,
	"SecurityMetricGUID" TEXT NULL,
	"DescriptionID" INTEGER NULL,
	"DescriptionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYMETRICREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYMETRICREFERENCE"(
	"SecurityMetricReferenceID" INTEGER NOT NULL,
	"SecurityMetricID" INTEGER NULL,
	"SecurityMetricGUID" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYMETRICTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYMETRICTAG"(
	"SecurityMetricTagID" INTEGER NOT NULL,
	"SecurityMetricID" INTEGER NULL,
	"SecurityMetricGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYNOTIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYNOTIFICATION"(
	"SecurityNotificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "SECURITYPRINCIPLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPRINCIPLE"(
	"SecurityPrincipleID" INTEGER NOT NULL,
	"SecurityPrincipleGUID" TEXT NULL,
	"SecurityPrincipleName" TEXT NOT NULL,
	"SecurityPrincipleDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYPRINCIPLEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPRINCIPLEDESCRIPTION"(
	"SecurityPrincipleDescriptionID" INTEGER NOT NULL,
	"SecurityPrincipleID" INTEGER NULL,
	"SecurityPrincipleGUID" TEXT NULL,
	"DescriptionID" INTEGER NULL,
	"DescriptionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYPRINCIPLEFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPRINCIPLEFORATTACKPATTERN"(
	"AttackPatternSecurityPrincipleID" INTEGER NOT NULL,
	"SecurityPrincipleID" INTEGER NOT NULL,
	"SecurityPrincipleGUID" TEXT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYPRINCIPLEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPRINCIPLEREFERENCE"(
	"SecurityPrincipleReferenceID" INTEGER NOT NULL,
	"SecurityPrincipleID" INTEGER NULL,
	"SecurityPrincipleGUID" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYPRINCIPLETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPRINCIPLETAG"(
	"SecurityPrincipleTagID" INTEGER NOT NULL,
	"SecurityPrincipleTagGUID" TEXT NULL,
	"SecurityPrincipleID" INTEGER NULL,
	"SecurityPrincipleGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYPROCESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPROCESS"(
	"SecurityProcessID" INTEGER NOT NULL,
	"SecurityProcessGUID" TEXT NULL,
	"SecurityProcessName" TEXT NULL,
	"SecurityProcessDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYPROCESSMATURITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPROCESSMATURITYLEVEL"(
	"SecurityProcessMaturityLevelID" INTEGER NOT NULL,
	"SecurityProcessMaturityLevelGUID" TEXT NULL,
	"SecurityProcessID" INTEGER NULL,
	"SecurityProcessGUID" TEXT NULL,
	"MaturityLevelID" INTEGER NULL,
	"MaturityLevelGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYPROGRAM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPROGRAM"(
	"SecurityProgramID" INTEGER NOT NULL,
	"SecurityProgramGUID" TEXT NULL,
	"SecurityProgramName" TEXT NOT NULL,
	"SecurityProgramDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"SecurityProgramTypeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYPROGRAMPROJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPROGRAMPROJECT"(
	"SecurityProgramProjectID" INTEGER NOT NULL,
	"SecurityProgramID" INTEGER NULL,
	"SecurityProgramGUID" TEXT NULL,
	"ProjectID" INTEGER NULL,
	"ProjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYPROGRAMTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYPROGRAMTYPE"(
	"SecurityProgramTypeID" INTEGER NOT NULL,
	"SecurityProgramTypeName" TEXT NOT NULL,
	"SecurityProgramTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYREQUIREMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYREQUIREMENT"(
	"SecurityRequirementID" INTEGER NOT NULL,
	"RequirementID" INTEGER NULL,
	"RequirementGUID" TEXT NULL,
	"SecurityRequirementGUID" TEXT NULL,
	"SecurityRequirementTitle" TEXT NULL,
	"SecurityRequirementDescription" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYREQUIREMENTCONTROL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYREQUIREMENTCONTROL"(
	"SecurityRequirementControlID" INTEGER NOT NULL,
	"SecurityRequirementID" INTEGER NULL,
	"SecurityRequirementGUID" TEXT NULL,
	"SecurityControlID" INTEGER NULL,
	"SecurityControlGUID" TEXT NULL,
	"EffectivenessID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYREQUIREMENTFORATTACKPATTERN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYREQUIREMENTFORATTACKPATTERN"(
	"AttackPatternSecurityRequirementID" INTEGER NOT NULL,
	"SecurityRequirementID" INTEGER NOT NULL,
	"SecurityRequirementGUID" TEXT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternGUID" TEXT NULL,
	"capec_id" TEXT NULL,
	"AttackPatternSecurityRequirementDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SECURITYREQUIREMENTMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYREQUIREMENTMAPPING"(
	"SecurityRequirementMappingID" INTEGER NOT NULL,
	"AssuranceRequirementID" INTEGER NULL,
	"AssuranceRequirementGUID" TEXT NULL,
	"SecurityRequirementRefID" INTEGER NOT NULL,
	"SecurityRequirementRefGUID" TEXT NULL,
	"SecurityRequirementRelationship" TEXT NULL,
	"SecurityRequirementDescription" TEXT NULL,
	"SecurityRequirementSubjectID" INTEGER NULL,
	"SecurityRequirementSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYREQUIREMENTTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYREQUIREMENTTAG"(
	"SecurityRequirementTagID" INTEGER NOT NULL,
	"SecurityRequirementID" INTEGER NULL,
	"SecurityRequirementGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYREQUIREMENTTEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYREQUIREMENTTEST"(
	"SecurityRequirementTestID" INTEGER NOT NULL,
	"SecurityRequirementTestGUID" TEXT NULL,
	"SecurityRequirementID" INTEGER NULL,
	"SecurityRequirementGUID" TEXT NULL,
	"TestID" INTEGER NULL,
	"TestGUID" TEXT NULL,
	"TestVocabularyID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SECURITYRISKANALYSIS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SECURITYRISKANALYSIS"(
	"SecurityRiskAnalysisID" INTEGER NOT NULL
)

;
/****** Object:  Table "SEMAPHORE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SEMAPHORE"(
	"SemaphoreID" INTEGER NOT NULL
)

;
/****** Object:  Table "SENSOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SENSOR"(
	"SensorID" INTEGER NOT NULL,
	"SensorGUID" TEXT NULL,
	"SensorName" TEXT NULL,
	"SensorDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"SensorVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SENSORTOOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SENSORTOOL"(
	"SensorToolID" INTEGER NOT NULL,
	"SensorID" INTEGER NOT NULL,
	"ToolID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"SensorToolDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "SERVICEACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SERVICEACTIONNAME"(
	"ServiceActionNameID" INTEGER NOT NULL,
	"ServiceActionNameName" TEXT NOT NULL,
	"ServiceActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SERVICECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SERVICECATEGORY"(
	"ServiceCategoryID" INTEGER NOT NULL,
	"ServiceCategoryName" TEXT NOT NULL,
	"ServiceCategoryDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"StatusID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SESSION"(
	"SessionID" INTEGER NOT NULL,
	"UserID" TEXT NULL,
	"SessionIDValue" TEXT NULL,
	"SessionName" TEXT NULL,
	"SessionDescription" TEXT NULL,
	"DateStart" TEXT NULL,
	"DateEnd" TEXT NULL,
	"StatusID" INTEGER NULL,
	"Status" TEXT NULL,
	"ServiceCategoryID" INTEGER NULL,
	"Parameters" BLOB NULL,
	"SessionCronID" INTEGER NULL,
	"information" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SESSIONCOOKIE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SESSIONCOOKIE"(
	"SessionCookieID" INTEGER NOT NULL,
	"SessionID" INTEGER NOT NULL,
	"SessionGUID" TEXT NULL,
	"CookieID" INTEGER NOT NULL,
	"CookieGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"SessionCookieName" TEXT NULL,
	"SessionCookieDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SESSIONCOOKIEATTRIBUTEVALUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SESSIONCOOKIEATTRIBUTEVALUE"(
	"SessionCookieAttributeValueID" INTEGER NOT NULL,
	"SessionCookieID" INTEGER NOT NULL,
	"SessionCookieGUID" TEXT NULL,
	"AttributeValueID" INTEGER NOT NULL,
	"AttributeValueGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"SessionCookieAttributeValueName" TEXT NULL,
	"SessionCookieAttributeValueDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SESSIONCRON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SESSIONCRON"(
	"SessionCronID" INTEGER NOT NULL,
	"UserID" TEXT NULL,
	"CronExpression" TEXT NULL,
	"Parameters" BLOB NULL,
	"StatusID" INTEGER NULL,
	"Status" TEXT NULL,
	"ServiceCategoryID" INTEGER NULL,
	"DateStart" TEXT NULL,
	"DateEnd" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SETOPERATOR"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SETOPERATOR"(
	"SetOperatorID" INTEGER NOT NULL,
	"SetOperatorValue" TEXT NOT NULL,
	"SetOperatorDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SEVERITYLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SEVERITYLEVEL"(
	"SeverityLevelID" INTEGER NOT NULL,
	"SeverityLevelGUID" TEXT NULL,
	"SeverityLevelName" TEXT NOT NULL,
	"SeverityLevelDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SHELLCODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SHELLCODE"(
	"ShellCodeID" INTEGER NOT NULL,
	"CodeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ShellCodeName" TEXT NULL,
	"ShellCodeDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "SIDTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIDTYPE"(
	"SIDTypeID" INTEGER NOT NULL,
	"SIDTypeName" TEXT NOT NULL,
	"SIDTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SIGNAL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNAL"(
	"SignalID" INTEGER NOT NULL
)

;
/****** Object:  Table "SIGNATURE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATURE"(
	"SignatureID" INTEGER NOT NULL,
	"SignatureName" TEXT NOT NULL,
	"SignatureDescription" TEXT NULL,
	"SignatureBase64Binary" TEXT NULL,
	"SeverityLevelID" INTEGER NULL,
	"SignatureSeverityLevel" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"SignatureTypeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SIGNATURECPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATURECPE"(
	"CPESignatureID" INTEGER NOT NULL,
	"SignatureID" INTEGER NOT NULL,
	"CPEID" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	"SignatureCPEName" TEXT NULL,
	"SignatureCPEDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SIGNATUREEXPLOIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATUREEXPLOIT"(
	"ExploitSignatureID" INTEGER NOT NULL,
	"SignatureID" INTEGER NOT NULL,
	"ExploitID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"SignatureExploitName" TEXT NULL,
	"SignatureExploitDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"TrustLevelID" INTEGER NULL
)

;
/****** Object:  Table "SIGNATUREMALWAREINSTANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATUREMALWAREINSTANCE"(
	"MalwareInstanceSignatureID" INTEGER NOT NULL,
	"SignatureID" INTEGER NOT NULL,
	"MalwareInstanceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"SignatureMalwareInstanceName" TEXT NULL,
	"SignatureMalwareInstanceDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "SIGNATUREPORT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATUREPORT"(
	"SignatureID" INTEGER NOT NULL,
	"PortID" INTEGER NOT NULL
)

;
/****** Object:  Table "SIGNATUREPROTOCOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATUREPROTOCOL"(
	"SignatureID" INTEGER NOT NULL,
	"ProtocolID" INTEGER NOT NULL
)

;
/****** Object:  Table "SIGNATUREREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATUREREFERENCE"(
	"SignatureReferenceID" INTEGER NOT NULL,
	"SignatureID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SIGNATURETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATURETYPE"(
	"SignatureTypeID" INTEGER NOT NULL,
	"SignatureTypeName" TEXT NOT NULL,
	"SignatureTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SIGNATURETYPEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIGNATURETYPEREFERENCE"(
	"SitgnatureTypeReferenceID" INTEGER NOT NULL,
	"SignatureTypeID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "SIMPLEDATATYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SIMPLEDATATYPE"(
	"SimpleDataTypeID" INTEGER NOT NULL,
	"DataTypeName" TEXT NOT NULL,
	"DataTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SKILL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SKILL"(
	"SkillID" INTEGER NOT NULL,
	"SkillGUID" TEXT NULL,
	"SkillName" TEXT NULL,
	"SkillDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SKILLCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SKILLCATEGORY"(
	"SkillCategoryID" INTEGER NOT NULL,
	"SkillCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"SkillCategoryName" TEXT NULL,
	"SkillCategoryDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SKILLCATEGORYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SKILLCATEGORYTAG"(
	"SkillCategoryTagID" INTEGER NOT NULL,
	"SkillCategoryID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SKILLLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SKILLLEVEL"(
	"SkillLevelID" INTEGER NOT NULL,
	"SkillLevelValue" TEXT NULL,
	"SkillLevelDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SKILLTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SKILLTAG"(
	"SkillTagID" INTEGER NOT NULL,
	"SkillID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SMSMESSAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SMSMESSAGE"(
	"SMSMessageID" INTEGER NOT NULL,
	"MessageID" INTEGER NULL
)

;
/****** Object:  Table "SOCKETACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOCKETACTIONNAME"(
	"SocketActionNameID" INTEGER NOT NULL,
	"SocketActionNameName" TEXT NOT NULL,
	"SocketActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "SOCKETADDRESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOCKETADDRESS"(
	"SocketAddressID" INTEGER NOT NULL,
	"AddressID" INTEGER NULL,
	"HostNameID" INTEGER NULL,
	"PortID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SOFTWARE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOFTWARE"(
	"SoftwareID" INTEGER NOT NULL,
	"SoftwareGUID" TEXT NULL,
	"ProductID" INTEGER NULL,
	"ProductGUID" TEXT NULL,
	"ApplicationID" INTEGER NULL,
	"ApplicationGUID" TEXT NULL,
	"CPEID" INTEGER NULL,
	"SWIDTAG" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SOFTWARECHARACTERISTIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOFTWARECHARACTERISTIC"(
	"SoftwareCharacteristicID" INTEGER NOT NULL
)

;
/****** Object:  Table "SOFTWAREFILELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOFTWAREFILELIST"(
	"SoftwareFileListID" INTEGER NOT NULL
)

;
/****** Object:  Table "SOFTWARELICENSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOFTWARELICENSE"(
	"SoftwareLicenseID" INTEGER NOT NULL,
	"SoftwareID" INTEGER NOT NULL,
	"SoftwareGUID" TEXT NULL,
	"LicenseID" INTEGER NOT NULL,
	"LicenseGUID" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL
)

;
/****** Object:  Table "SOURCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOURCE"(
	"SourceID" INTEGER NOT NULL,
	"SourceGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SOURCECLASS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOURCECLASS"(
	"SourceClassID" INTEGER NOT NULL,
	"SourceClassName" TEXT NOT NULL,
	"SourceClassDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SOURCETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SOURCETYPE"(
	"SourceTypeID" INTEGER NOT NULL,
	"SourceTypeName" TEXT NOT NULL,
	"SourceTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SPLITFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SPLITFUNCTION"(
	"SplitFunctionID" INTEGER NOT NULL,
	"SplitDelimiter" TEXT NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL
)

;
/****** Object:  Table "SPYINGSTRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SPYINGSTRATEGICOBJECTIVE"(
	"SpyingStrategicObjectiveID" INTEGER NOT NULL,
	"SpyingStrategicObjectiveName" TEXT NULL,
	"SpyingStrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SPYINGTACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SPYINGTACTICALOBJECTIVE"(
	"SpyingTacticalObjectiveID" INTEGER NOT NULL,
	"SpyingTacticalObjectiveName" TEXT NULL,
	"SpyingTacticalObjectiveDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SSDTENTRY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SSDTENTRY"(
	"SSDTEntryID" INTEGER NOT NULL,
	"Service_Table_Base" TEXT NULL,
	"Service_Counter_Table_Base" TEXT NULL,
	"Number_Of_Services" INTEGER NULL,
	"Argument_Table_Base" TEXT NULL,
	"hooked" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "STAGE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STAGE"(
	"StageID" INTEGER NOT NULL,
	"StageGUID" TEXT NULL,
	"StageName" TEXT NULL,
	"StageDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "STAGECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STAGECATEGORY"(
	"StageCategoryID" INTEGER NOT NULL,
	"CategoryID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "STAGEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STAGEDESCRIPTION"(
	"StageDescriptionID" INTEGER NOT NULL,
	"StageID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "STANDARD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARD"(
	"StandardID" INTEGER NOT NULL,
	"StandardGUID" TEXT NULL,
	"StandardVocabularyID" TEXT NULL,
	"StandardName" TEXT NOT NULL,
	"StandardDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "STANDARDCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDCATEGORY"(
	"StandardCategoryID" INTEGER NOT NULL,
	"CategoryID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "STANDARDOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDOBJECTIVE"(
	"StandardObjectiveID" INTEGER NOT NULL,
	"StandardObjectiveVocabularyID" TEXT NULL,
	"StandardID" INTEGER NULL,
	"ObjectiveID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "STANDARDORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDORGANISATION"(
	"StandardOrganisationID" INTEGER NOT NULL,
	"StandardID" INTEGER NOT NULL,
	"RelationshipName" TEXT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "STANDARDREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDREFERENCE"(
	"StandardReferenceID" INTEGER NOT NULL,
	"StandardID" INTEGER NOT NULL,
	"StandardGUID" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "STANDARDRELATIONSHIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDRELATIONSHIP"(
	"StandardRelationshipID" INTEGER NOT NULL,
	"StandardRefID" INTEGER NOT NULL,
	"RelationshipName" TEXT NULL,
	"StandardSubjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ReferenceURL" TEXT NULL
)

;
/****** Object:  Table "STANDARDSECTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDSECTION"(
	"StandardSectionID" INTEGER NOT NULL,
	"StandardID" INTEGER NULL,
	"StandardGUID" TEXT NULL,
	"SectionID" INTEGER NULL,
	"SectionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "STANDARDSECTIONMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDSECTIONMAPPING"(
	"StandardSectionMappingID" INTEGER NOT NULL,
	"StandardSectionRefID" INTEGER NULL,
	"StandardSectionSubjectID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"MappingComment" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "STANDARDSECURITYREQUIREMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDSECURITYREQUIREMENT"(
	"StandardSecurityRequirementID" INTEGER NOT NULL,
	"StandardID" INTEGER NULL,
	"SecurityRequirementID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "STANDARDTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDTAG"(
	"StandardTagID" INTEGER NOT NULL,
	"StandardID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "STANDARDVOCABULARY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STANDARDVOCABULARY"(
	"StandardVocabularyID" INTEGER NOT NULL,
	"StandardID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "STARTUPINFO"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STARTUPINFO"(
	"StartupInfoID" INTEGER NOT NULL,
	"lpDesktop" TEXT NULL,
	"lpTitle" TEXT NULL,
	"dwX" INTEGER NULL,
	"dwY" INTEGER NULL,
	"dwXSize" INTEGER NULL,
	"dwYSize" INTEGER NULL,
	"dwXCountChars" INTEGER NULL,
	"dwYCountChars" INTEGER NULL,
	"dwFillAttribute" INTEGER NULL,
	"dwFlags" INTEGER NULL,
	"wShowWindow" INTEGER NULL
)

;
/****** Object:  Table "STATUS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STATUS"(
	"StatusID" INTEGER NOT NULL,
	"StatusName" TEXT NOT NULL,
	"StatusDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "STRATEGICOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STRATEGICOBJECTIVE"(
	"StrategicObjectiveID" INTEGER NOT NULL,
	"StrategicObjectiveGUID" TEXT NULL,
	"ObjectiveID" INTEGER NULL,
	"StrategicObjectiveName" TEXT NULL,
	"StrategicObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "STRATEGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STRATEGY"(
	"StrategyID" INTEGER NOT NULL
)

;
/****** Object:  Table "STRUCTUREDAUTHENTICATIONMECHANISM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "STRUCTUREDAUTHENTICATIONMECHANISM"(
	"StructuredAuthenticationMechanismID" INTEGER NOT NULL,
	"StructuredAuthenticationMechanismGUID" TEXT NULL,
	"StructuredAuthenticationMechanismDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SUBCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SUBCATEGORY"(
	"SubCategoryID" INTEGER NOT NULL,
	"CategoryParentID" INTEGER NOT NULL,
	"CategoryID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL
)

;
/****** Object:  Table "SUBJECTPUBLICKEY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SUBJECTPUBLICKEY"(
	"SubjectPublicKeyID" INTEGER NOT NULL,
	"Public_Key_Algorithm" TEXT NOT NULL,
	"EncryptionID" INTEGER NULL,
	"RSA_Public_Key" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SUBSTRINGFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SUBSTRINGFUNCTION"(
	"SubstringFunctionID" INTEGER NOT NULL,
	"SubstringStart" INTEGER NOT NULL,
	"SubstringLength" INTEGER NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL
)

;
/****** Object:  Table "SUPPLYCHAIN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SUPPLYCHAIN"(
	"SupplyChainID" INTEGER NOT NULL
)

;
/****** Object:  Table "SUPPLYCHAINASSURANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SUPPLYCHAINASSURANCE"(
	"SupplyChainAssuranceID" INTEGER NOT NULL
)

;
/****** Object:  Table "SUPPLYCHAINCOMPLIANCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SUPPLYCHAINCOMPLIANCE"(
	"SupplyChainComplianceID" INTEGER NOT NULL
)

;
/****** Object:  Table "SUPPRESSIONTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SUPPRESSIONTYPE"(
	"SuppressionTypeID" INTEGER NOT NULL,
	"SuppressionTypeName" TEXT NULL,
	"SuppressionTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SUSPECTEDMALICIOUSREASON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SUSPECTEDMALICIOUSREASON"(
	"SuspectedMaliciousReasonID" INTEGER NOT NULL,
	"SuspectedMaliciousReasonGUID" TEXT NULL,
	"SuspectedMaliciousReasonName" TEXT NULL,
	"ReasonID" INTEGER NULL,
	"SuspectedMaliciousReasonDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "SWENTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SWENTAG"(
	"SWENTAGID" INTEGER NOT NULL
)

;
/****** Object:  Table "SWIDTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SWIDTAG"(
	"SWIDTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "SWIDTAGCPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SWIDTAGCPE"(
	"SWIDTagCPEID" INTEGER NOT NULL
)

;
/****** Object:  Table "SYNCHRONIZATIONACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SYNCHRONIZATIONACTIONNAME"(
	"SynchronizationActionNameID" INTEGER NOT NULL,
	"SynchronizationActionNameName" TEXT NOT NULL,
	"SynchronizationActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SYSTEM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SYSTEM"(
	"SystemID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL
)

;
/****** Object:  Table "SYSTEMACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SYSTEMACTIONNAME"(
	"SystemActionNameID" INTEGER NOT NULL,
	"SystemActionNameName" TEXT NOT NULL,
	"SystemActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "SYSTEMINFO"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SYSTEMINFO"(
	"SystemInfoID" INTEGER NOT NULL,
	"OSID" INTEGER NOT NULL,
	"architecture" TEXT NOT NULL,
	"primaryhostname" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "SYSTEMINFOFOROVALSYSTEMCHARACTERISTICS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SYSTEMINFOFOROVALSYSTEMCHARACTERISTICS"(
	"OVALSystemCharacteristicsID" INTEGER NOT NULL,
	"SystemInfo" INTEGER NOT NULL
)

;
/****** Object:  Table "SYSTEMTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SYSTEMTYPE"(
	"SystemTypeID" INTEGER NOT NULL,
	"SystemTypeGUID" TEXT NULL,
	"SystemTypeName" TEXT NOT NULL,
	"SystemTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "SYSTEMTYPEFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SYSTEMTYPEFORASSET"(
	"AssetSystemTypeID" INTEGER NOT NULL,
	"AssetID" INTEGER NOT NULL,
	"SystemTypeID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "SYSTEMTYPEFORTHREATACTORTTP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "SYSTEMTYPEFORTHREATACTORTTP"(
	"SystemTypeID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL
)

;
/****** Object:  Table "TACTIC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TACTIC"(
	"TacticID" INTEGER NOT NULL
)

;
/****** Object:  Table "TACTICALOBJECTIVE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TACTICALOBJECTIVE"(
	"TacticalObjectiveID" INTEGER NOT NULL,
	"TacticalObjectiveGUID" TEXT NULL,
	"ObjectiveID" INTEGER NULL,
	"TacticalObjectiveName" TEXT NULL,
	"TacticalObjectiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TACTICCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TACTICCATEGORY"(
	"TacticCategoryID" INTEGER NOT NULL,
	"CategoryID" INTEGER NULL
)

;
/****** Object:  Table "TAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAG"(
	"TagID" INTEGER NOT NULL,
	"TagGUID" TEXT NULL,
	"TagValue" TEXT NULL,
	"casesensitive" INTEGER NULL,
	"TagDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"TagType" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ToolID" INTEGER NULL,
	"ToolGUID" TEXT NULL,
	"SourceID" INTEGER NULL,
	"SourceGUID" TEXT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"AccountID" INTEGER NULL,
	"AccountGUID" TEXT NULL,
	"UserID" INTEGER NULL,
	"UserGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"VocabularyGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "TAGBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAGBLACKLIST"(
	"TagBlacklistID" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TAGCLASSIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAGCLASSIFICATION"(
	"TagClassificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "TAGFORASSET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAGFORASSET"(
	"TagAssetID" INTEGER NOT NULL,
	"AssetID" INTEGER NULL,
	"AssetGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagValue" TEXT NULL,
	"TagAssetDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TAGRESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAGRESTRICTION"(
	"TagRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "TAGTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAGTAG"(
	"TagTagID" INTEGER NOT NULL,
	"TagTagGUID" TEXT NULL,
	"TagParentID" INTEGER NULL,
	"TagParentGUID" TEXT NULL,
	"TagSubjectID" INTEGER NULL,
	"TagSubjectGUID" TEXT NULL,
	"TagRelationship" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"SourceID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ImportanceID" INTEGER NULL
)

;
/****** Object:  Table "TARGET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TARGET"(
	"TargetID" INTEGER NOT NULL
)

;
/****** Object:  Table "TARGETEDPLATFORMS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TARGETEDPLATFORMS"(
	"TargetedPlatformsID" INTEGER NOT NULL
)

;
/****** Object:  Table "TARGETEDPLATFORMSPECIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TARGETEDPLATFORMSPECIFICATION"(
	"TargetedPlatformsSpecification" INTEGER NOT NULL,
	"TargetedPlatformsID" INTEGER NOT NULL,
	"PlatformSpecificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "TARGETS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TARGETS"(
	"TargetsID" INTEGER NOT NULL
)

;
/****** Object:  Table "TASK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASK"(
	"TaskID" INTEGER NOT NULL,
	"TaskName" TEXT NULL,
	"TaskDescription" TEXT NULL,
	"TaskPriority" TEXT NULL,
	"TaskStatus" TEXT NULL,
	"CompletionPercentage" REAL NULL,
	"ExpectedCompletionDate" TEXT NULL,
	"StartDate" TEXT NULL,
	"DueDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TASKACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKACTION"(
	"TaskActionID" INTEGER NOT NULL
)

;
/****** Object:  Table "TASKACTIONLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKACTIONLIST"(
	"TaskActionListID" INTEGER NOT NULL
)

;
/****** Object:  Table "TASKACTIONTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKACTIONTYPE"(
	"TaskActionTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "TASKATTACHMENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKATTACHMENT"(
	"TaskAttachmentID" INTEGER NOT NULL,
	"TaskID" INTEGER NULL,
	"Title" TEXT NULL,
	"Data" BLOB NULL,
	"MimeType" TEXT NULL
)

;
/****** Object:  Table "TASKDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKDESCRIPTION"(
	"TaskDescriptionID" INTEGER NOT NULL,
	"TaskID" INTEGER NOT NULL,
	"TaskGUID" TEXT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TASKFLAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKFLAG"(
	"TaskFlagID" INTEGER NOT NULL
)

;
/****** Object:  Table "TASKFORPROJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKFORPROJECT"(
	"ProjectTaskID" INTEGER NOT NULL,
	"ProjectID" INTEGER NOT NULL,
	"TaskID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"ProjectTaskName" TEXT NULL,
	"ProjectTaskDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TASKPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKPERSON"(
	"TaskID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"RelationshipType" TEXT NULL
)

;
/****** Object:  Table "TASKPRIORITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKPRIORITY"(
	"TaskPriorityID" INTEGER NOT NULL
)

;
/****** Object:  Table "TASKPRIORITYENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKPRIORITYENUM"(
	"TaskPriorityEnumID" INTEGER NOT NULL,
	"TaskPriority" TEXT NULL,
	"TaskPriorityDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TASKSTATUS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKSTATUS"(
	"TaskStatusID" INTEGER NOT NULL
)

;
/****** Object:  Table "TASKSTATUSENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKSTATUSENUM"(
	"TaskStatusEnumID" INTEGER NOT NULL,
	"Status" TEXT NULL,
	"TaskStatusDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TASKTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKTAG"(
	"TaskTagID" INTEGER NOT NULL,
	"TaskID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TASKTRIGGER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKTRIGGER"(
	"TaskTriggerID" INTEGER NOT NULL
)

;
/****** Object:  Table "TASKTRIGGERFREQUENCY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TASKTRIGGERFREQUENCY"(
	"TaskTriggerFrequencyID" INTEGER NOT NULL
)

;
/****** Object:  Table "TAXONOMY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAXONOMY"(
	"TaxonomyID" INTEGER NOT NULL,
	"TaxonomyName" TEXT NOT NULL,
	"TaxonomyDescription" TEXT NULL,
	"TaxonomyVersion" TEXT NULL,
	"TaxonomyReference" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"DateModified" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TAXONOMYNODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAXONOMYNODE"(
	"TaxonomyNodeID" INTEGER NOT NULL,
	"TaxonomyID" INTEGER NULL,
	"TaxonomyNodeName" TEXT NULL,
	"TaxonomyMappedNodeID" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"TaxonomyNodeDescription" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TAXONOMYREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TAXONOMYREFERENCE"(
	"TaxonomyReferenceID" INTEGER NOT NULL,
	"TaxonomyID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"TaxonomyReferenceName" TEXT NULL,
	"TaxonomyReferenceDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TCPSTATE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TCPSTATE"(
	"TCPStateID" INTEGER NOT NULL,
	"TCPStateValue" TEXT NULL,
	"TCPStateDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TECHNICALCONTEXT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNICALCONTEXT"(
	"TechnicalContextID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TECHNIQUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNIQUE"(
	"TechniqueID" INTEGER NOT NULL,
	"TechniqueGUID" TEXT NULL,
	"TechniqueName" TEXT NULL,
	"TechniqueDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"ValidityID" INTEGER NULL,
	"CreationObjectID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TECHNIQUECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNIQUECATEGORY"(
	"TechniqueCategoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "TECHNIQUEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNIQUEDESCRIPTION"(
	"TechniqueDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "TECHNIQUEREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNIQUEREFERENCE"(
	"TechniqueReferenceID" INTEGER NOT NULL,
	"TechniqueID" INTEGER NOT NULL,
	"TechniqueGUID" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"TechniqueReferenceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidentialityLevelID" INTEGER NULL
)

;
/****** Object:  Table "TECHNIQUEREFERENCETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNIQUEREFERENCETAG"(
	"TechniqueReferenceTagID" INTEGER NOT NULL,
	"TechniqueReferenceID" INTEGER NULL,
	"TechniqueReferenceGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"ConfidentialityLevelID" INTEGER NULL
)

;
/****** Object:  Table "TECHNIQUERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNIQUERESTRICTION"(
	"TechniqueRestrictionID" INTEGER NOT NULL
)

;
/****** Object:  Table "TECHNIQUESTEP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNIQUESTEP"(
	"TechniqueStepID" INTEGER NOT NULL
)

;
/****** Object:  Table "TECHNIQUETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNIQUETAG"(
	"TechniqueTagID" INTEGER NOT NULL,
	"TechniqueID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TECHNOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNOLOGY"(
	"TechnologyID" INTEGER NOT NULL,
	"TechnologyGUID" TEXT NULL,
	"TechnologyName" TEXT NULL,
	"TechnologyDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TECHNOLOGYDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNOLOGYDESCRIPTION"(
	"TechnologyDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "TECHNOLOGYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNOLOGYTAG"(
	"TechnologyTagID" INTEGER NOT NULL,
	"TechnologyID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TECHNOLOGYURI"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TECHNOLOGYURI"(
	"TechnologyURIID" INTEGER NOT NULL,
	"TechnologyID" INTEGER NOT NULL,
	"URIObjectID" INTEGER NOT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TELEPHONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TELEPHONE"(
	"TelephoneID" INTEGER NOT NULL,
	"TelephoneGUID" TEXT NULL,
	"TelephoneNumber" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TELEPHONECALL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TELEPHONECALL"(
	"TelephoneCallID" INTEGER NOT NULL
)

;
/****** Object:  Table "TELEPHONEFORORGANISATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TELEPHONEFORORGANISATION"(
	"OrganisationTelephoneID" INTEGER NOT NULL,
	"TelephoneID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TELEPHONEFORPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TELEPHONEFORPERSON"(
	"PersonTelephoneID" INTEGER NOT NULL,
	"TelephoneID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TELEPHONETAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TELEPHONETAG"(
	"TelephoneTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "TEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TEST"(
	"TestID" INTEGER NOT NULL,
	"TestGUID" TEXT NULL,
	"TestName" TEXT NULL,
	"TestDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TESTMECHANISMEFFICACY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TESTMECHANISMEFFICACY"(
	"TestMechanismEfficacyID" INTEGER NOT NULL,
	"Efficacy" TEXT NOT NULL,
	"EfficacyDescription" TEXT NULL,
	"ConfidenceLevel" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TESTMECHANISMID"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TESTMECHANISMID"(
	"TestMechanismID" INTEGER NOT NULL,
	"CyberObservableTestMechanismID" INTEGER NOT NULL,
	"TestMechanismIDREF" TEXT NOT NULL,
	"Information_Source" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THEORETICALNOTE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "THEORETICALNOTE"(
	"TheoreticalNoteID" INTEGER NOT NULL,
	"TheoreticalNoteText" TEXT NULL,
	"TheoreticalNoteTextClean" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREADRUNNINGSTATUS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "THREADRUNNINGSTATUS"(
	"ThreadRunningStatusID" INTEGER NOT NULL,
	"Running_Status" TEXT NOT NULL,
	"ThreadRunningStatusDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TICKET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TICKET"(
	"TicketID" INTEGER NOT NULL,
	"TicketGUID" TEXT NULL,
	"StatusID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TICKETCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TICKETCHANGERECORD"(
	"TicketChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "TICKETCHANGEREQUEST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TICKETCHANGEREQUEST"(
	"TicketChangeRequestID" INTEGER NOT NULL
)

;
/****** Object:  Table "TICKETNOTIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TICKETNOTIFICATION"(
	"TicketNotificationID" INTEGER NOT NULL
)

;
/****** Object:  Table "TICKETRACIMATRIX"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TICKETRACIMATRIX"(
	"TicketRACIMatrixID" INTEGER NOT NULL
)

;
/****** Object:  Table "TIMEDIFFERENCEFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TIMEDIFFERENCEFUNCTION"(
	"TimeDifferenceFunctionID" INTEGER NOT NULL,
	"DateTimeFormat1" TEXT NOT NULL,
	"DateTimeFormat2" TEXT NOT NULL
)

;
/****** Object:  Table "TIMELINE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TIMELINE"(
	"TimelineID" INTEGER NOT NULL
)

;
/****** Object:  Table "TIMESHEET"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TIMESHEET"(
	"TimesheetID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"TimesheetName" TEXT NULL,
	"TimesheetDescription" TEXT NULL,
	"TimeValue" REAL NULL,
	"TimeUnitID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ProjectID" INTEGER NULL,
	"TaskID" INTEGER NULL,
	"ProjectTaskID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TIMESHEETPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TIMESHEETPERSON"(
	"TimesheetPersonID" INTEGER NOT NULL,
	"TimesheetID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"PersonRole" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"TimesheetPersonDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"StatusID" INTEGER NULL,
	"SignatureID" INTEGER NULL
)

;
/****** Object:  Table "TIMEUNIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TIMEUNIT"(
	"TimeUnitID" INTEGER NOT NULL,
	"TimeUnit" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"TimeUnitDescription" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TIP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TIP"(
	"TipID" INTEGER NOT NULL,
	"TipGUID" TEXT NULL,
	"TipName" TEXT NULL,
	"TipDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TIPCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TIPCATEGORY"(
	"TipCategoryID" INTEGER NOT NULL,
	"TipCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"TipCategoryName" TEXT NULL,
	"TipCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TIPREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TIPREFERENCE"(
	"TipReferenceID" INTEGER NOT NULL,
	"TipID" INTEGER NOT NULL,
	"TipGUID" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"TipReferenceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TITLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TITLE"(
	"TitleID" INTEGER NOT NULL,
	"TitleText" TEXT NULL,
	"LocaleID" INTEGER NULL,
	"VersionID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TOKEN"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOKEN"(
	"TokenID" INTEGER NOT NULL,
	"TokenParentID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"TokenName" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TOOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOL"(
	"ToolID" INTEGER NOT NULL,
	"ToolGUID" TEXT NULL,
	"ToolName" TEXT NOT NULL,
	"ToolDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"ReliabilityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TOOLDOCUMENT"    Script Date: 06/20/2026 00:00:00 ******/

CREATE TABLE "TOOLDOCUMENT"(
	"ToolDocumentID" INTEGER NOT NULL,
	"ToolDocumentGUID" TEXT NULL,
	"ToolID" INTEGER NULL,
	"DocumentID" INTEGER NULL,
	"CreatedDate" DATE NULL,
	"PersonID" INTEGER NULL,
	"ValidFrom" DATE NULL,
	"ValidUntil" DATE NULL,
	"ConfidenceLevel" TEXT NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "TOOLACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLACCESSRECORD"(
	"ToolAccessRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "TOOLCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLCHANGERECORD"(
	"ToolChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "TOOLCODE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLCODE"(
	"ToolCodeID" INTEGER NOT NULL,
	"ToolCodeGUID" TEXT NULL,
	"ToolID" INTEGER NULL,
	"ToolGUID" TEXT NULL,
	"CodeID" INTEGER NULL,
	"CodeGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CreationObjectGUID" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionMethodGUID" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceLevelGUID" TEXT NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ConfidenceReasonGUID" TEXT NULL,
	"SourceID" INTEGER NULL,
	"SourceGUID" TEXT NULL,
	"RepositoryID" INTEGER NULL,
	"RepositoryGUID" TEXT NULL
)

;
/****** Object:  Table "TOOLFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLFUNCTION"(
	"ToolFunctionID" INTEGER NOT NULL,
	"ToolFunctionGUID" TEXT NULL,
	"ToolID" INTEGER NULL,
	"ToolGUID" TEXT NULL,
	"FunctionID" INTEGER NULL,
	"FunctionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TOOLINFORMATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLINFORMATION"(
	"ToolInformationID" INTEGER NOT NULL,
	"ToolInformationGUID" TEXT NULL,
	"ToolInformationIDREF" TEXT NULL,
	"ToolName" TEXT NOT NULL,
	"ToolDescription" TEXT NULL,
	"Vendor" TEXT NULL,
	"Version" TEXT NULL,
	"Service_Pack" TEXT NULL,
	"Tool_Specific_Data" TEXT NULL,
	"Tool_Hashes" TEXT NULL,
	"Tool_Configuration" TEXT NULL,
	"Execution_Environment" TEXT NULL,
	"Errors" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TOOLINFORMATIONDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLINFORMATIONDESCRIPTION"(
	"ToolInformationDescriptionID" INTEGER NOT NULL,
	"ToolInformationID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TOOLINFORMATIONFORTOOL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLINFORMATIONFORTOOL"(
	"ToolInformationForToolID" INTEGER NOT NULL,
	"ToolID" INTEGER NOT NULL,
	"ToolInformationID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TOOLINFORMATIONMETADATA"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLINFORMATIONMETADATA"(
	"ToolInformationID" INTEGER NOT NULL,
	"MetadataID" INTEGER NOT NULL
)

;
/****** Object:  Table "TOOLINFORMATIONREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLINFORMATIONREFERENCE"(
	"ToolInformationReferenceID" INTEGER NOT NULL,
	"ToolInformationID" INTEGER NOT NULL,
	"ToolInformationGUID" TEXT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"ToolReferenceTypeID" INTEGER NULL,
	"ToolReferenceTypeGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TOOLLICENSE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLLICENSE"(
	"ToolLicenseID" INTEGER NOT NULL,
	"ToolID" INTEGER NOT NULL,
	"LicenseID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "TOOLREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLREFERENCE"(
	"ToolReferenceID" INTEGER NOT NULL,
	"ToolID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ToolReferenceTypeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidentialityLevelID" INTEGER NULL
)

;
/****** Object:  Table "TOOLREFERENCETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLREFERENCETYPE"(
	"ToolReferenceTypeID" INTEGER NOT NULL,
	"ToolReferenceTypeName" TEXT NOT NULL,
	"ToolReferenceTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TOOLREPOSITORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLREPOSITORY"(
	"ToolRepositoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "TOOLTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLTAG"(
	"ToolTagID" INTEGER NOT NULL,
	"ToolTagGUID" TEXT NULL,
	"ToolID" INTEGER NULL,
	"ToolGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValdFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TOOLTECHNOLOGY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLTECHNOLOGY"(
	"ToolTechnologyID" INTEGER NOT NULL
)

;
/****** Object:  Table "TOOLTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLTYPE"(
	"ToolTypeID" INTEGER NOT NULL,
	"ToolTypeGUID" TEXT NULL,
	"ToolTypeName" TEXT NOT NULL,
	"ToolTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NOT NULL,
	"isEncrypted" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "TOOLTYPEFORTOOLINFORMATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLTYPEFORTOOLINFORMATION"(
	"ToolInformationID" INTEGER NOT NULL,
	"ToolTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "TOOLUSERAGENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TOOLUSERAGENT"(
	"ToolUserAgentID" INTEGER NOT NULL,
	"ToolID" INTEGER NULL,
	"UserAgentID" INTEGER NULL
)

;
/****** Object:  Table "TRAINING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRAINING"(
	"TrainingID" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TRAININGFORPERSON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRAININGFORPERSON"(
	"TrainingPersonID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"TrainingID" INTEGER NOT NULL
)

;
/****** Object:  Table "TRANSACTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRANSACTION"(
	"TransactionID" INTEGER NOT NULL,
	"UserID" TEXT NULL,
	TEXT TEXT NULL,
	"Amount" REAL NULL,
	"Status" TEXT NULL,
	"OrderNumber" TEXT NULL,
	"Email" TEXT NULL,
	"City" TEXT NULL,
	"ProductID" TEXT NULL,
	"ProductDescription" TEXT NULL,
	"HolderName" TEXT NULL,
	"PaymentMethod" TEXT NULL
)

;
/****** Object:  Table "TRANSFORMATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRANSFORMATION"(
	"TransformationID" INTEGER NOT NULL
)

;
/****** Object:  Table "TREND"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TREND"(
	"TrendID" INTEGER NOT NULL,
	"TrendName" TEXT NOT NULL,
	"TrendDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TRIGGERFREQUENCYENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRIGGERFREQUENCYENUM"(
	"TriggerFrequencyEnumID" INTEGER NOT NULL,
	"TriggerFrequency" TEXT NULL,
	"TriggerFrequencyDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "TRIGGERLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRIGGERLIST"(
	"TriggerListID" INTEGER NOT NULL
)

;
/****** Object:  Table "TRIGGERTYPEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRIGGERTYPEENUM"(
	"TriggerTypeEnumID" INTEGER NOT NULL,
	"TriggerType" TEXT NULL,
	"TriggerTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "TRUSTLEVEL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRUSTLEVEL"(
	"TrustLevelID" INTEGER NOT NULL,
	"TrustLevelGUID" TEXT NULL,
	"TrustLevelName" TEXT NOT NULL,
	"TrustLevelDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TRUSTREASON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TRUSTREASON"(
	"TrustReasonID" INTEGER NOT NULL,
	"TrustReasonGUID" TEXT NULL,
	"ReasonID" INTEGER NULL,
	"TrustReasonName" TEXT NULL,
	"TrustReasonDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "TYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "TYPE"(
	"TypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "UNIDIRECTIONALFLOWRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIDIRECTIONALFLOWRECORD"(
	"UnidirectionalFlowRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "UNIQUEFUNCTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIQUEFUNCTION"(
	"UniqueFunctionID" INTEGER NOT NULL
)

;
/****** Object:  Table "UNIT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIT"(
	"UnitID" INTEGER NOT NULL
)

;
/****** Object:  Table "UNIXFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIXFILE"(
	"UnixFileID" INTEGER NOT NULL
)

;
/****** Object:  Table "UNIXNETWORKROUTEENTRY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIXNETWORKROUTEENTRY"(
	"UnixNetworkRouteEntryID" INTEGER NOT NULL
)

;
/****** Object:  Table "UNIXPIPEOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIXPIPEOBJECT"(
	"UnixPipeObjectID" INTEGER NOT NULL
)

;
/****** Object:  Table "UNIXPROCESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIXPROCESS"(
	"UnixProcessID" INTEGER NOT NULL
)

;
/****** Object:  Table "UNIXUSERACCOUNT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIXUSERACCOUNT"(
	"UnixUserAccountID" INTEGER NOT NULL,
	"AccountID" INTEGER NULL
)

;
/****** Object:  Table "UNIXVOLUME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "UNIXVOLUME"(
	"UnixVolumeID" INTEGER NOT NULL,
	"VolumeObjectID" INTEGER NULL
)

;
/****** Object:  Table "URGENCY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "URGENCY"(
	"UrgencyID" INTEGER NOT NULL
)

;
/****** Object:  Table "URIOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "URIOBJECT"(
	"URIObjectID" INTEGER NOT NULL,
	"URIValue" TEXT NULL,
	"URITypeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "URITYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "URITYPE"(
	"URITypeID" INTEGER NOT NULL,
	"URITypeName" TEXT NULL,
	"URITypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "URL"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "URL"(
	"URLID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NULL
)

;
/****** Object:  Table "URLHISTORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "URLHISTORY"(
	"URLHistoryID" INTEGER NOT NULL,
	"URLHistoryGUID" TEXT NULL,
	"BrowserToolInformationID" INTEGER NULL,
	"ToolInformationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "URLHISTORYENTRIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "URLHISTORYENTRIES"(
	"URLHistoryEntriesID" INTEGER NOT NULL,
	"URLHistoryID" INTEGER NULL,
	"URLHistoryGUID" TEXT NULL,
	"URLHistoryEntryID" INTEGER NULL,
	"URLHistoryEntryGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "URLHISTORYENTRY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "URLHISTORYENTRY"(
	"URLHistoryEntryID" INTEGER NOT NULL,
	"URLHistoryEntryGUID" TEXT NULL,
	"URIObjectID" INTEGER NULL,
	"HostnameID" INTEGER NULL,
	"Referrer_URL" INTEGER NULL,
	"Page_Title" TEXT NULL,
	"User_Profile_Name" TEXT NULL,
	"Visit_Count" INTEGER NULL,
	"Manually_Entered_Count" INTEGER NULL,
	"Modification_DateTime" TEXT NULL,
	"Expiration_DateTime" TEXT NULL,
	"First_Visit_DateTime" TEXT NULL,
	"Last_Visit_DateTime" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"CollectionMethoID" INTEGER NULL
)

;
/****** Object:  Table "USAGETYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USAGETYPE"(
	"UsageTypeID" INTEGER NOT NULL,
	"TypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "USECASE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USECASE"(
	"UseCaseID" INTEGER NOT NULL,
	"UseCaseGUID" TEXT NULL,
	"UseCaseDescription" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "USECASECATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USECASECATEGORY"(
	"UseCaseCategoryID" INTEGER NOT NULL,
	"UseCaseCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"UseCasecategoryName" TEXT NULL,
	"UseCaseCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "USECASEFORBUSINESSRISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USECASEFORBUSINESSRISK"(
	"BusinessRiskUseCaseID" INTEGER NOT NULL,
	"BusinessRiskUseCaseGUID" TEXT NULL,
	"UseCaseID" INTEGER NOT NULL,
	"UseCaseGUID" TEXT NULL,
	"BusinessRiskID" INTEGER NOT NULL,
	"BusinessRiskGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "USECASEFORREGULATORYRISK"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USECASEFORREGULATORYRISK"(
	"RegulatoryRiskUseCaseID" INTEGER NOT NULL,
	"RegulatoryRiskUseCaseGUID" TEXT NULL,
	"UseCaseID" INTEGER NOT NULL,
	"UseCaseGUID" TEXT NULL,
	"RegulatoryRiskID" INTEGER NOT NULL,
	"RegulatoryRiskGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "USER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USER"(
	"UserID" INTEGER NOT NULL,
	"UserGUID" TEXT NULL,
	"UserName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromdate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "USERACCOUNT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USERACCOUNT"(
	"UserAccountID" INTEGER NOT NULL,
	"AccountID" INTEGER NULL,
	"UserID" TEXT NULL,
	"UserAccountACL" INTEGER NULL,
	"UserAccountTypeID" INTEGER NULL,
	"UserAccountTypeName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "USERACCOUNTTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USERACCOUNTTYPE"(
	"UserAccountTypeID" INTEGER NOT NULL,
	"UserAccountTypeGUID" TEXT NULL,
	"UserAccountTypeName" TEXT NULL,
	"UserAccountTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "USERACTIONNAME"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USERACTIONNAME"(
	"UserActionNameID" INTEGER NOT NULL,
	"UserActionNameName" TEXT NOT NULL,
	"UserActionNameDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "USERAGENT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USERAGENT"(
	"UserAgentID" INTEGER NOT NULL,
	"UserAgentGUID" TEXT NULL
)

;
/****** Object:  Table "USERAGENTBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USERAGENTBLACKLIST"(
	"UserAgentBlacklistID" INTEGER NOT NULL,
	"UserAgentBlacklistGUID" TEXT NULL,
	"UserAgentBlacklistName" TEXT NULL,
	"UserAgentBlacklistDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "USERAGENTCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USERAGENTCATEGORY"(
	"UserAgentCategoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "USERSESSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "USERSESSION"(
	"UserSessionID" INTEGER NOT NULL
)

;
/****** Object:  Table "VALIDITY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VALIDITY"(
	"ValidityID" INTEGER NOT NULL,
	"Not_Before" TEXT NULL,
	"Not_After" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "VALUE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VALUE"(
	"ValueID" INTEGER NOT NULL,
	"ValueValue" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "VALUEBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VALUEBLACKLIST"(
	"ValueBlacklistID" INTEGER NOT NULL,
	"ValueID" INTEGER NULL
)

;
/****** Object:  Table "VALUEGROUP"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VALUEGROUP"(
	"ValueGroupID" INTEGER NOT NULL
)

;
/****** Object:  Table "VALUEMAPPING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VALUEMAPPING"(
	"ValueMappingID" INTEGER NOT NULL
)

;
/****** Object:  Table "VALUEWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VALUEWHITELIST"(
	"ValueWhitelistID" INTEGER NOT NULL,
	"ValueID" INTEGER NULL
)

;
/****** Object:  Table "VARIABLE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VARIABLE"(
	"VariableID" INTEGER NOT NULL
)

;
/****** Object:  Table "VERSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VERSION"(
	"VersionID" INTEGER NOT NULL,
	"VersionValue" TEXT NULL,
	"VersionDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "VIEWPORT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VIEWPORT"(
	"ViewPortID" INTEGER NOT NULL
)

;
/****** Object:  Table "VOCABULARY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOCABULARY"(
	"VocabularyID" INTEGER NOT NULL,
	"VocabularyGUID" TEXT NULL,
	"VocabularyName" TEXT NOT NULL,
	"VocabularyVersion" TEXT NULL,
	"VocabularyReference" TEXT NULL,
	"DateModified" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "VOCABULARYCATEGORIES"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOCABULARYCATEGORIES"(
	"VocabularyCategoriesID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"VocabularyCategoryID" INTEGER NULL,
	"CategoryID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "VOCABULARYCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOCABULARYCATEGORY"(
	"VocabularyCategoryID" INTEGER NOT NULL,
	"VocabularyCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"VocabularyCategoryName" TEXT NULL,
	"VocabularyCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "VOCABULARYCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOCABULARYCHANGERECORD"(
	"VocabularyChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "VOCABULARYDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOCABULARYDESCRIPTION"(
	"VocabularyDescriptionID" INTEGER NOT NULL,
	"VocabularyDescribedID" INTEGER NOT NULL,
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
/****** Object:  Table "VOCABULARYREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOCABULARYREFERENCE"(
	"VocabularyID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"VocabularyReferenceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "VOCABULARYTAG"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOCABULARYTAG"(
	"VocabularyTagID" INTEGER NOT NULL,
	"VocabularyTaggedID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL
)

;
/****** Object:  Table "VOCABULARYVERSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOCABULARYVERSION"(
	"VocabularyVersionID" INTEGER NOT NULL,
	"VocabularyVersionGUID" TEXT NULL,
	"VocabularyID" INTEGER NOT NULL,
	"VocabularyGUID" TEXT NULL,
	"VersionID" INTEGER NOT NULL,
	"ChangeLog" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "VOLUMEOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VOLUMEOBJECT"(
	"VolumeObjectID" INTEGER NOT NULL
)

;
/****** Object:  Table "VULNERABLECONFIGURATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VULNERABLECONFIGURATION"(
	"VulnerableConfigurationID" INTEGER NOT NULL,
	"VulnerabilityID" INTEGER NULL,
	"ConfigurationOrder" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "VULNERABLECONFIGURATIONCPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "VULNERABLECONFIGURATIONCPE"(
	"VulnerableConfigurationCPEID" INTEGER NOT NULL,
	"VulnerableConfigurationID" INTEGER NULL,
	"LogicalTestLevel" INTEGER NULL,
	"LogicalTestLevelOrder" INTEGER NULL,
	"CPELogicalTestID" INTEGER NULL,
	"CPEID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WAITABLETIMERTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WAITABLETIMERTYPE"(
	"WaitableTimerTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "WAITABLETIMERTYPEENUM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WAITABLETIMERTYPEENUM"(
	"WaitaibleTimerTypeEnumID" INTEGER NOT NULL,
	"WaitaibleTimerTypeName" TEXT NOT NULL,
	"WaitableTimerTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "WAIVER"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WAIVER"(
	"WaiverID" INTEGER NOT NULL,
	"WaiverName" TEXT NULL,
	"WaiverDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WAIVERREASON"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WAIVERREASON"(
	"WaiverReasonID" INTEGER NOT NULL
)

;
/****** Object:  Table "WARNING"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WARNING"(
	"WarningID" INTEGER NOT NULL,
	"WarningText" TEXT NOT NULL,
	"lang" TEXT NULL,
	"WarningCategoryID" INTEGER NULL
)

;
/****** Object:  Table "WARNINGCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WARNINGCATEGORY"(
	"WarningCategoryID" INTEGER NOT NULL,
	"WarningCategoryName" TEXT NOT NULL,
	"WarningCategoryMeaning" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"lang" TEXT NULL
)

;
/****** Object:  Table "WASC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WASC"(
	"WASCID" INTEGER NOT NULL,
	"WASCThreatType" TEXT NOT NULL,
	"WASCRefID" TEXT NOT NULL,
	"WASCName" TEXT NULL,
	"WASCDescription" TEXT NULL,
	"WASCExample" TEXT NULL,
	"WASCRefURL" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WASCCWE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WASCCWE"(
	"WASCCWEID" INTEGER NOT NULL,
	"WASCID" INTEGER NOT NULL,
	"WASCRefID" TEXT NULL,
	"CWEID" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WASCFORCAPEC"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WASCFORCAPEC"(
	"WASCForCAPECID" INTEGER NOT NULL,
	"WASCID" INTEGER NOT NULL,
	"WASCRefID" TEXT NULL,
	"AttackPatternID" INTEGER NULL,
	"capec_id" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WASCREFERENCE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WASCREFERENCE"(
	"WASCReferenceID" INTEGER NOT NULL,
	"WASCID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WASCTHREATTYPE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WASCTHREATTYPE"(
	"WASCThreatTypeID" INTEGER NOT NULL,
	"ThreatTypeID" INTEGER NOT NULL,
	"WASCID" INTEGER NOT NULL
)

;
/****** Object:  Table "WEAKNESS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WEAKNESS"(
	"WeaknessID" INTEGER NOT NULL,
	"WeaknessGUID" TEXT NULL,
	"CWEID" TEXT NULL,
	"WeaknessName" TEXT NULL,
	"WeaknessDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WEAKNESSCWE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WEAKNESSCWE"(
	"WeaknessCWEID" INTEGER NOT NULL,
	"WeaknessCWEGUID" TEXT NULL,
	"WeaknessID" INTEGER NOT NULL,
	"WeaknessGUID" TEXT NULL,
	"CWEID" TEXT NULL,
	"WeaknessCWEDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WHOISCHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WHOISCHANGERECORD"(
	"WhoisChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "WHOISOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WHOISOBJECT"(
	"WhoisObjectID" INTEGER NOT NULL,
	"WhoisObjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WORD"(
	"WordID" INTEGER NOT NULL,
	"WordGUID" TEXT NULL,
	"WordValue" TEXT NULL,
	"LocaleID" INTEGER NULL,
	"WordDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WORDBLACKLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WORDBLACKLIST"(
	"WordBlacklistID" INTEGER NOT NULL,
	"WordListID" INTEGER NULL
)

;
/****** Object:  Table "WORDFILE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WORDFILE"(
	"WordFileID" INTEGER NOT NULL,
	"FileID" INTEGER NULL
)

;
/****** Object:  Table "WORDLIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WORDLIST"(
	"WordListID" INTEGER NOT NULL,
	"WordListGUID" TEXT NULL,
	"VersionID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WORDLISTCATEGORY"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WORDLISTCATEGORY"(
	"WordListCategoryID" INTEGER NOT NULL
)

;
/****** Object:  Table "WORDLISTWORDS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WORDLISTWORDS"(
	"WordListWordID" INTEGER NOT NULL,
	"WordListID" INTEGER NOT NULL,
	"WordID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL
)

;
/****** Object:  Table "WORDWHITELIST"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WORDWHITELIST"(
	"WordWhitelistID" INTEGER NOT NULL,
	"WordListID" INTEGER NULL
)

;
/****** Object:  Table "WORKINGHOURS"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "WORKINGHOURS"(
	"WorkingHoursID" INTEGER NOT NULL
)

;
/****** Object:  Table "X509CERTIFICATE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509CERTIFICATE"(
	"X509CertificateID" INTEGER NOT NULL,
	"X509CertificateGUID" TEXT NULL,
	"CertificateID" INTEGER NULL,
	"Version" INTEGER NULL,
	"Serial_Number" TEXT NULL,
	"Signature_Algorithm" TEXT NULL,
	"EncryptionID" INTEGER NULL,
	"Issuer" TEXT NULL,
	"IssuerOrganisationID" INTEGER NULL,
	"ValidityID" INTEGER NULL,
	"Subject" TEXT NULL,
	"SubjectOrganisationID" INTEGER NULL,
	"SubjectPersonID" INTEGER NULL,
	"Subject_Public_Key" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "X509CERTIFICATEACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509CERTIFICATEACCESSRECORD"(
	"X509CertificateAccessRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "X509CERTIFICATECHANGERECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509CERTIFICATECHANGERECORD"(
	"X509CertificateChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "X509CERTIFICATENONSTANDARDEXTENSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509CERTIFICATENONSTANDARDEXTENSION"(
	"X509CertificateNonStandardExtensionID" INTEGER NOT NULL,
	"X509CertificateID" INTEGER NOT NULL,
	"X509NonStandardExtensionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "X509CERTIFICATEOBJECT"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509CERTIFICATEOBJECT"(
	"X509CertificateObjectID" INTEGER NOT NULL,
	"X509CertificateID" INTEGER NOT NULL,
	"X509CertificateGUID" TEXT NULL,
	"X509SignatureID" INTEGER NOT NULL,
	"X509SignatureGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "X509CERTIFICATESTANDARDEXTENSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509CERTIFICATESTANDARDEXTENSION"(
	"X509CertificateStandardExtensionID" INTEGER NOT NULL,
	"X509CertificateID" INTEGER NOT NULL,
	"X509CertificateGUID" TEXT NULL,
	"X509V3ExtensionID" INTEGER NOT NULL,
	"X509V3ExtensionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "X509NONSTANDARDEXTENSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509NONSTANDARDEXTENSION"(
	"X509NonStandardExtensionID" INTEGER NOT NULL,
	"X509NonStandardExtensionGUID" TEXT NULL,
	"Netscape_Comment" TEXT NULL,
	"Netscape_Certificate_Type" TEXT NULL,
	"Old_Authority_Key_Identifier" TEXT NULL,
	"Old_Primary_Key_Attributes" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "X509SIGNATURE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509SIGNATURE"(
	"X509SignatureID" INTEGER NOT NULL,
	"X509SignatureGUID" TEXT NULL,
	"SignatureID" INTEGER NULL,
	"Signature_Algorithm" TEXT NULL,
	"EncryptionID" INTEGER NULL,
	"Signature" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "X509V3EXTENSION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509V3EXTENSION"(
	"X509V3ExtensionID" INTEGER NOT NULL,
	"X509V3ExtensionGUID" TEXT NULL,
	"Basic_Constraints" TEXT NULL,
	"Name_Constraints" TEXT NULL,
	"Policy_Constraints" TEXT NULL,
	"Key_Usage" TEXT NULL,
	"Extended_Key_Usage" TEXT NULL,
	"Subject_Key_Identifier" TEXT NULL,
	"Authority_Key_Identifier" TEXT NULL,
	"Subject_Alternative_Name" TEXT NULL,
	"Issuer_Alternative_Name" TEXT NULL,
	"Subject_Directory_Attributes" TEXT NULL,
	"CRL_Distribution_Points" TEXT NULL,
	"Inhibit_Any_Policy" INTEGER NULL,
	"Private_Key_Usage_Period" INTEGER NULL,
	"Certificate_Policies" TEXT NULL,
	"Policy_Mappings" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "X509V3EXTENSIONACCESSRECORD"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509V3EXTENSIONACCESSRECORD"(
	"X509V3ExtensionAccessRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "X509V3EXTENSIONPOLICYTERM"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "X509V3EXTENSIONPOLICYTERM"(
	"X509V3ExtensionPolicyTermID" INTEGER NOT NULL,
	"X509V3ExtensionID" INTEGER NOT NULL,
	"PolicyTermID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ZONE"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ZONE"(
	"ZoneID" INTEGER NOT NULL,
	"ZoneGUID" TEXT NULL,
	"ZoneName" TEXT NULL,
	"ZoneDescription" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ZONECLASSIFICATION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ZONECLASSIFICATION"(
	"ZoneClassificationID" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ZONEDESCRIPTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ZONEDESCRIPTION"(
	"ZoneDescriptionID" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ZONERESTRICTION"    Script Date: 04/03/2015 19:59:09 ******/

;

;
CREATE TABLE "ZONERESTRICTION"(
	"ZoneRestrictionID" INTEGER NOT NULL,
	"isEncrypted" INTEGER NULL
)

;



;
/****** XORCISM schema catch-up — generated 2026-06-14 (schema catch-up, no asterisk-slash here) ******/
;

-- New tables
CREATE TABLE IF NOT EXISTS "BIAAUDIT" (
    "BIAAuditID"          INTEGER PRIMARY KEY AUTOINCREMENT,
    "BIAAuditName"        TEXT NOT NULL,
    "BIAAuditDescription" TEXT,
    "BIAAuditScope"       TEXT,
    "BIAAuditDate"        TEXT,
    "BIAAuditStatus"      TEXT DEFAULT 'Draft',
    "Auditor"             TEXT,
    "CreatedDate"         TEXT,
    "CreatedByPersonID"   INTEGER
, "TenantID" INTEGER);
CREATE TABLE IF NOT EXISTS "BIAENTRY" (
    "BIAEntryID"           INTEGER PRIMARY KEY AUTOINCREMENT,
    "BIAAuditID"           INTEGER NOT NULL,
    "AssetID"              INTEGER,
    "AssetName"            TEXT,
    "AssetDescription"     TEXT,
    "AssetType"            TEXT,
    "CriticalityLevel"     TEXT,
    "OwnerPersonID"        INTEGER,
    "OwnerName"            TEXT,
    "RiskDescription"      TEXT,
    "RiskLevel"            TEXT,
    "ImpactFinancial"      TEXT,
    "ImpactOperational"    TEXT,
    "ImpactLegal"          TEXT,
    "ImpactReputational"   TEXT,
    "MTD"                  TEXT,
    "RTO"                  TEXT,
    "RPO"                  TEXT,
    "Notes"                TEXT,
    "CreatedDate"          TEXT,
    "ModifiedDate"         TEXT, "TenantID" INTEGER,
    FOREIGN KEY (BIAAuditID) REFERENCES BIAAUDIT(BIAAuditID)
);
-- Directed dependency edges between BIA entries ("From depends on To"), drives the BIA dependency graph.
CREATE TABLE IF NOT EXISTS "BIADEPENDENCY" (
    "BIADependencyID"      INTEGER PRIMARY KEY,
    "BIAAuditID"           INTEGER,
    "FromEntryID"          INTEGER,
    "ToEntryID"            INTEGER,
    "DependencyType"       TEXT,
    "Notes"                TEXT,
    "CreatedDate"          TEXT,
    "TenantID"             INTEGER
);
CREATE INDEX IF NOT EXISTS ix_biadep_audit ON BIADEPENDENCY(BIAAuditID);
CREATE TABLE IF NOT EXISTS "ACCOUNTTYPE"(
    "AccountTypeID" INTEGER NOT NULL,
    "AccountTypeName" TEXT NULL,
    "AccountTypeDescription" TEXT NULL,
    "VocabularyID" INTEGER NULL
);
CREATE TABLE IF NOT EXISTS "ASSETVULNERABILITY"(
    "AssetVulnerabilityID" INTEGER NOT NULL PRIMARY KEY,
    "AssetID" INTEGER NULL,
    "VulnerabilityID" INTEGER NULL,
    "CreatedDate" TEXT NULL,
    "ValidFromDate" TEXT NULL,
    "ValidUntilDate" TEXT NULL,
    "ToolID" INTEGER NULL
, "TenantID" INTEGER, "AssetVulnerabilityStatusID" INTEGER, "Status" INTEGER, "TotalControl" INTEGER, "FalsePositive" INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS THREATMODEL (
      ThreatModelID INTEGER PRIMARY KEY,
      ThreatModelGUID TEXT, ThreatModelName TEXT, Description TEXT,
      Methodology TEXT, Status TEXT, Scope TEXT, RiskLevel TEXT, Owner TEXT,
      CreatedDate TEXT, VocabularyID INTEGER, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS THREATMODELASSET (
      ThreatModelAssetID INTEGER PRIMARY KEY,
      ThreatModelID INTEGER, AssetID INTEGER, CreatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS THREATMODELTHREAT (
      ThreatModelThreatID INTEGER PRIMARY KEY,
      ThreatModelID INTEGER, Title TEXT, STRIDECategory TEXT, Description TEXT,
      ThreatAgentID INTEGER, AttackPattern TEXT, Likelihood TEXT, Impact TEXT,
      RiskScore TEXT, Status TEXT, CreatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS THREATMODELCONTROL (
      ThreatModelControlID INTEGER PRIMARY KEY,
      ThreatModelThreatID INTEGER, ControlID INTEGER, Status TEXT,
      CreatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS "ASSETRISKSCORE" (
  "AssetRiskScoreID" INTEGER PRIMARY KEY,
  "Date" TEXT,
  "RiskScore" INTEGER,
  "ConfidenceLevel" INTEGER,
  "TrustLevel" INTEGER
, "AssetID" INTEGER);
CREATE TABLE IF NOT EXISTS "RISKSCORE" (
  "RiskScoreID" INTEGER PRIMARY KEY,
  "RiskScore" INTEGER,
  "Date" TEXT,
  "TenantID" INTEGER,
  "ConfidenceLevel" INTEGER
);
CREATE TABLE IF NOT EXISTS "ASSETTHREAT" ("AssetThreatID" INTEGER PRIMARY KEY, "AssetThreatGUID" TEXT, "AssetID" INTEGER, "ThreatID" INTEGER, "ValidFrom" DATE, "ValidUntil" TEXT, "ConfidenceLevel" INTEGER, "TrustLevel" INTEGER, "Criticity" INTEGER);
CREATE TABLE IF NOT EXISTS "ASSETAUDIT" ("AssetAuditID" INTEGER PRIMARY KEY, "AssetAuditGUID" TEXT, "AssetID" INTEGER, "AuditID" INTEGER, "Date" TEXT, "ValidFrom" DATE, "ValidUntil" TEXT, "ConfidenceLevel" INTEGER);
CREATE TABLE IF NOT EXISTS "ASSETAUDITFINDING" ("AssetAuditFindingID" INTEGER PRIMARY KEY, "AssetAuditFindingGUID" TEXT, "AssetID" INTEGER, "AuditFindingID" INTEGER, "Date" TEXT, "Status" TEXT, "ConfidenceLevel" INTEGER, "Criticity" INTEGER, "ValidFrom" DATE, "ValidUntil" TEXT);
CREATE TABLE IF NOT EXISTS "ASSETOVALDEFINITION" ("AssetOVALDefinitionID" INTEGER PRIMARY KEY, "AssetID" INTEGER, "OVALDefinitionID" INTEGER, "Status" TEXT, "ConfidenceLevel" TEXT, "CreatedDate" TEXT, "ValidFrom" DATE, "ValidUntil" TEXT);
CREATE TABLE IF NOT EXISTS "ASSETFINANCIALVALUE" ("AssetFinancialValueID" INTEGER PRIMARY KEY, "AssetID" INTEGER, "FinancialValue" INTEGER, "Currency" TEXT, "CreatedDate" TEXT, "ValidFrom" DATE, "ValidUntil" TEXT, "PersonID" INTEGER);
CREATE TABLE IF NOT EXISTS "VENDOR" ("VendorID" INTEGER PRIMARY KEY, "VendorName" TEXT, "VendorDescription" TEXT, "VendorURL" TEXT, "CreatedDate" TEXT, "ValidFrom" DATE, "ValidUntil" TEXT, "Source" TEXT, "ConfidenceLevel" TEXT, "TrustLevel" TEXT);
CREATE TABLE IF NOT EXISTS ASSETVULNERABILITYREMEDIATION (
      AssetVulnerabilityRemediationID INTEGER PRIMARY KEY,
      AssetVulnerabilityID INTEGER, RemediationName TEXT, RemediationDescription TEXT,
      CreatedDate TEXT, PersonID INTEGER, ValidFrom DATE, ValidUntil DATE);
CREATE TABLE IF NOT EXISTS APPLICATIONWHITELISTENTRY (
      AppWhitelistEntryID INTEGER PRIMARY KEY,
      ApplicationWhitelistID INTEGER, ApplicationID INTEGER,
      CreatedDate TEXT, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER, ConfidenceLevel TEXT);
CREATE TABLE IF NOT EXISTS APPLICATIONBLACKLISTENTRY (
      AppBlacklistEntryID INTEGER PRIMARY KEY,
      ApplicationBlacklistID INTEGER, ApplicationID INTEGER,
      CreatedDate TEXT, PersonID INTEGER, ValidFrom DATE, ValidUntil DATE, VocabularyID INTEGER);
CREATE TABLE IF NOT EXISTS ASSETTAG (
      AssetTagID INTEGER PRIMARY KEY,
      AssetID INTEGER, TagID INTEGER, Tag TEXT,
      CreatedDate TEXT, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER);
CREATE INDEX IF NOT EXISTS "ix_BIAAUDIT_tenant" ON "BIAAUDIT" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_BIAENTRY_tenant" ON "BIAENTRY" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_ASSETVULNERABILITY_tenant" ON "ASSETVULNERABILITY" ("TenantID");
CREATE INDEX IF NOT EXISTS ix_tmasset_model ON THREATMODELASSET(ThreatModelID);
CREATE INDEX IF NOT EXISTS ix_tmthreat_model ON THREATMODELTHREAT(ThreatModelID);
CREATE INDEX IF NOT EXISTS ix_tmcontrol_threat ON THREATMODELCONTROL(ThreatModelThreatID);
CREATE INDEX IF NOT EXISTS "ix_THREATMODEL_tenant" ON "THREATMODEL" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_THREATMODELASSET_tenant" ON "THREATMODELASSET" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_THREATMODELTHREAT_tenant" ON "THREATMODELTHREAT" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_THREATMODELCONTROL_tenant" ON "THREATMODELCONTROL" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_RISKSCORE_tenant" ON "RISKSCORE" ("TenantID");
CREATE INDEX IF NOT EXISTS ix_assetoval_asset ON ASSETOVALDEFINITION(AssetID);
CREATE INDEX IF NOT EXISTS ix_assetfinval_asset ON ASSETFINANCIALVALUE(AssetID);
CREATE INDEX IF NOT EXISTS ix_vendor_name ON VENDOR(VendorName);
CREATE INDEX IF NOT EXISTS ix_avremediation_av ON ASSETVULNERABILITYREMEDIATION(AssetVulnerabilityID);
CREATE INDEX IF NOT EXISTS ix_appwlentry_wl ON APPLICATIONWHITELISTENTRY(ApplicationWhitelistID);
CREATE INDEX IF NOT EXISTS ix_appblentry_bl ON APPLICATIONBLACKLISTENTRY(ApplicationBlacklistID);
CREATE INDEX IF NOT EXISTS ix_assettag_asset ON ASSETTAG(AssetID);

-- New columns on existing tables
ALTER TABLE "ACCESSRECORD" ADD COLUMN "AssetID" INTEGER;
ALTER TABLE "ACTION" ADD COLUMN "ActionName" TEXT;
ALTER TABLE "APPLICATIONBLACKLIST" ADD COLUMN "AppBlacklistName" TEXT;
ALTER TABLE "APPLICATIONBLACKLIST" ADD COLUMN "AppBlacklistDescription" TEXT;
ALTER TABLE "APPLICATIONBLACKLIST" ADD COLUMN "CreatedDate" TEXT;
ALTER TABLE "APPLICATIONBLACKLIST" ADD COLUMN "PersonID" INTEGER;
ALTER TABLE "APPLICATIONBLACKLIST" ADD COLUMN "ValidFrom" DATE;
ALTER TABLE "APPLICATIONBLACKLIST" ADD COLUMN "ValidUntil" DATE;
ALTER TABLE "APPLICATIONBLACKLIST" ADD COLUMN "ConfidenceLevel" TEXT;
ALTER TABLE "APPLICATIONWHITELIST" ADD COLUMN "AppWhitelistName" TEXT;
ALTER TABLE "APPLICATIONWHITELIST" ADD COLUMN "AppWhitelistDescription" TEXT;
ALTER TABLE "APPLICATIONWHITELIST" ADD COLUMN "CreatedDate" TEXT;
ALTER TABLE "APPLICATIONWHITELIST" ADD COLUMN "ValidFrom" DATE;
ALTER TABLE "APPLICATIONWHITELIST" ADD COLUMN "ValidUntil" DATE;
ALTER TABLE "APPLICATIONWHITELIST" ADD COLUMN "PersonID" INTEGER;
ALTER TABLE "APPLICATIONWHITELIST" ADD COLUMN "VocabularyID" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "TenantID" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "AssetImage" TEXT;
ALTER TABLE "ASSET" ADD COLUMN "PublicFacing" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "PersonID" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "PlatformID" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "RiskScore" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "AssetLocation" TEXT;
ALTER TABLE "ASSET" ADD COLUMN "FinancialValue" REAL;
ALTER TABLE "ASSET" ADD COLUMN "Currency" TEXT;
ALTER TABLE "ASSET" ADD COLUMN "HostPII" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "BusinessValue" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "SLAResponseHours" REAL;
ALTER TABLE "ASSET" ADD COLUMN "SLAResolutionHours" REAL;
ALTER TABLE "ASSET" ADD COLUMN "Backed" INTEGER;
ALTER TABLE "ASSET" ADD COLUMN "BackupPlanID" INTEGER;
ALTER TABLE "ASSETLOCATION" ADD COLUMN "AssetLocationName" TEXT;
ALTER TABLE "CONFIDENTIALITYLEVEL" ADD COLUMN "ConfidentialityLevelName" TEXT;
ALTER TABLE "CONFIDENTIALITYLEVEL" ADD COLUMN "ConfidentialityLevelDescription" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "ISO" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "NIST" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "CIS" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "Minimal" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "Balanced" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "Comprehensive" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "D3FEND" TEXT;
ALTER TABLE "CPEFORASSET" ADD COLUMN "TenantID" INTEGER;
ALTER TABLE "NOTIFICATION" ADD COLUMN "Title" TEXT;
ALTER TABLE "NOTIFICATION" ADD COLUMN "Level" TEXT;
ALTER TABLE "NOTIFICATION" ADD COLUMN "Link" TEXT;
ALTER TABLE "NOTIFICATION" ADD COLUMN "Source" TEXT;
ALTER TABLE "NOTIFICATION" ADD COLUMN "IsRead" INTEGER;
ALTER TABLE "NOTIFICATION" ADD COLUMN "ReadDate" TEXT;
ALTER TABLE "NOTIFICATION" ADD COLUMN "TenantID" INTEGER;
-- NOTE: PERSON.email is already declared in the CREATE TABLE "PERSON" above, so a
-- migration ALTER here would fail on a fresh create with "duplicate column name: email"
-- (better-sqlite3 exec() aborts the whole script on the first error, so XORCISM.db was
-- never created on a clean install). The redundant ALTER has been removed intentionally.
ALTER TABLE "POLICY" ADD COLUMN "Status" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "Version" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "PolicyReference" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "OwnerPersonID" INTEGER;
ALTER TABLE "POLICY" ADD COLUMN "ApprovedByPersonID" INTEGER;
ALTER TABLE "POLICY" ADD COLUMN "EffectiveDate" DATE;
ALTER TABLE "POLICY" ADD COLUMN "ReviewDate" DATE;
ALTER TABLE "POLICY" ADD COLUMN "Category" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "Framework" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "Clause" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "Classification" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "Language" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "Scope" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "PolicyContent" TEXT;
ALTER TABLE "POLICY" ADD COLUMN "ApprovedDate" DATE;
ALTER TABLE "POLICY" ADD COLUMN "TenantID" INTEGER;
ALTER TABLE "TOOL" ADD COLUMN "Category" TEXT;
ALTER TABLE "TOOL" ADD COLUMN "ToolURL" TEXT;
ALTER TABLE "VOCABULARY" ADD COLUMN "VocabularyDescription" TEXT;
ALTER TABLE "TRAINING" ADD COLUMN "TrainingGUID" TEXT;
ALTER TABLE "TRAINING" ADD COLUMN "TrainingName" TEXT;
ALTER TABLE "TRAINING" ADD COLUMN "TrainingDescription" TEXT;
ALTER TABLE "TRAINING" ADD COLUMN "ValidFrom" DATE;
ALTER TABLE "TRAINING" ADD COLUMN "ValidUntil" TEXT;
ALTER TABLE "TRAINING" ADD COLUMN "Status" TEXT;
ALTER TABLE "TRAININGFORPERSON" ADD COLUMN "DateEnrolled" TEXT;
ALTER TABLE "TRAININGFORPERSON" ADD COLUMN "DateCompleted" TEXT;
ALTER TABLE "TRAININGFORPERSON" ADD COLUMN "Status" TEXT;
ALTER TABLE "TRAININGFORPERSON" ADD COLUMN "ConfidenceLevel" INTEGER;
ALTER TABLE "TRAININGFORPERSON" ADD COLUMN "ValidFrom" DATE;
ALTER TABLE "TRAININGFORPERSON" ADD COLUMN "ValidUntil" TEXT;
ALTER TABLE "TRAININGFORPERSON" ADD COLUMN "TenantID" INTEGER;

-- Pentest tool-chaining ("attack playbooks") — see xorcism_ts/server/chain.ts (ensureChainTables).
-- A playbook is a rule graph; a run executes it from a seed target; each step is a tool run
-- whose facts (ports/services/tech/vulns) trigger the follow-on tools.
CREATE TABLE IF NOT EXISTS "XCHAINPLAYBOOK" (
  "PlaybookID" INTEGER PRIMARY KEY, "PlaybookGUID" TEXT, "Name" TEXT, "Description" TEXT,
  "Definition" TEXT, "Builtin" INTEGER DEFAULT 0, "TenantID" INTEGER, "CreatedDate" TEXT, "CreatedBy" INTEGER);
CREATE TABLE IF NOT EXISTS "XCHAINRUN" (
  "ChainRunID" INTEGER PRIMARY KEY, "ChainRunGUID" TEXT, "AuditID" INTEGER, "PlaybookID" INTEGER,
  "PlaybookName" TEXT, "Name" TEXT, "SeedTarget" TEXT, "SeedKind" TEXT, "Mode" TEXT,
  "Status" TEXT DEFAULT 'running', "TenantID" INTEGER, "CreatedDate" TEXT, "CreatedBy" INTEGER,
  "FinishedDate" TEXT, "StepsTotal" INTEGER DEFAULT 0, "FindingsTotal" INTEGER DEFAULT 0,
  "BackingEngagementID" INTEGER);
CREATE TABLE IF NOT EXISTS "XCHAINSTEP" (
  "ChainStepID" INTEGER PRIMARY KEY, "ChainRunID" INTEGER, "ParentStepID" INTEGER, "Depth" INTEGER,
  "Connector" TEXT, "Target" TEXT, "RuleID" TEXT, "RuleLabel" TEXT, "JobID" INTEGER,
  "Status" TEXT DEFAULT 'pending', "FactsJSON" TEXT, "Summary" TEXT, "CreatedDate" TEXT, "FinishedDate" TEXT);
CREATE INDEX IF NOT EXISTS ix_chainrun_audit ON XCHAINRUN(AuditID);
CREATE INDEX IF NOT EXISTS ix_chainstep_run ON XCHAINSTEP(ChainRunID);

-- Attack-surface drift snapshots — see xorcism_ts/server/drift.ts (ensureDriftTable).
CREATE TABLE IF NOT EXISTS "XSURFACESNAPSHOT" (
  "SnapshotID" INTEGER PRIMARY KEY, "TenantID" INTEGER, "CreatedDate" TEXT, "CreatedBy" INTEGER,
  "AssetCount" INTEGER, "ExposedCount" INTEGER, "Payload" TEXT);
CREATE INDEX IF NOT EXISTS ix_surfsnap_tenant ON XSURFACESNAPSHOT(TenantID, SnapshotID);

-- ASSET ↔ CONTROL mapping (which security controls apply to which asset) — see ensureAssetColumns().
CREATE TABLE IF NOT EXISTS "ASSETCONTROL" (
  "AssetControlID" INTEGER PRIMARY KEY,
  "AssetControlGUID" TEXT,
  "AssetID" INTEGER,
  "ControlID" INTEGER,
  "CreatedDate" DATE,
  "PersonID" INTEGER,
  "Status" TEXT,
  "ValidFrom" DATE,
  "ValidUntil" DATE,
  "ConfidenceLevel" TEXT,
  "ConfidenceReasonID" INTEGER,
  "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_assetcontrol_asset ON "ASSETCONTROL"("AssetID");
CREATE INDEX IF NOT EXISTS ix_assetcontrol_control ON "ASSETCONTROL"("ControlID");

-- Backup & recovery plan for an ASSET (referenced by ASSET.BackupPlanID).
CREATE TABLE IF NOT EXISTS "BACKUPPLAN" (
  "BackupPlanID" INTEGER PRIMARY KEY,
  "BackupPlanGUID" TEXT,
  "BackupPlanName" TEXT,
  "Description" TEXT,
  "AssetID" INTEGER,
  "Type" TEXT,
  "Frequency" INTEGER,
  "FrequencyUnit" TEXT,
  "LastRun" DATE,
  "LastTested" DATE,
  "RetentionDays" INTEGER,
  "StorageLocation" TEXT,
  "RPOHours" REAL,
  "RTOHours" REAL,
  "PersonID" INTEGER,
  "Status" TEXT,
  "CreatedDate" DATE,
  "ValidFrom" DATE,
  "ValidUntil" DATE,
  "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_backupplan_asset ON "BACKUPPLAN"("AssetID");

-- Identity & Access Management (IAM) registry: human + non-human identities.
CREATE TABLE IF NOT EXISTS "IDENTITY" (
  "IdentityID" INTEGER PRIMARY KEY,
  "IdentityGUID" TEXT,
  "IdentityName" TEXT,
  "IdentityType" TEXT,
  "IdentityClass" TEXT,
  "Description" TEXT,
  "Status" TEXT,
  "OwnerPersonID" INTEGER,
  "AssetID" INTEGER,
  "Provider" TEXT,
  "ExternalID" TEXT,
  "PrivilegeLevel" TEXT,
  "Environment" TEXT,
  "CredentialType" TEXT,
  "MFAEnabled" TEXT,
  "LastRotatedDate" DATE,
  "ExpiryDate" DATE,
  "LastUsedDate" DATE,
  "RiskLevel" TEXT,
  "CreatedDate" DATE,
  "ModifiedDate" DATE,
  "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_identity_owner ON "IDENTITY"("OwnerPersonID");
CREATE INDEX IF NOT EXISTS ix_identity_asset ON "IDENTITY"("AssetID");
CREATE INDEX IF NOT EXISTS ix_identity_type ON "IDENTITY"("IdentityType");

-- Junction: human identity <-> PERSON (a person may hold several identities).
CREATE TABLE IF NOT EXISTS "IDENTITYPERSON" (
  "IdentityPersonID" INTEGER PRIMARY KEY,
  "IdentityPersonGUID" TEXT,
  "IdentityID" INTEGER,
  "PersonID" INTEGER,
  "RelationshipType" TEXT,
  "CreatedDate" DATE,
  "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_identityperson_identity ON "IDENTITYPERSON"("IdentityID");
CREATE INDEX IF NOT EXISTS ix_identityperson_person ON "IDENTITYPERSON"("PersonID");

-- NIST SP 800-53 control management (ensureControlImplementationTables, control53.ts).
-- Baseline membership + rich text on the (shared) 800-53 catalogue rows — global NIST facts, filled
-- by import_nist80053_baselines.py (baselines) and import_nist80053_details.py (statement/guidance…).
ALTER TABLE "CONTROL" ADD COLUMN "BaselineLow" INTEGER;
ALTER TABLE "CONTROL" ADD COLUMN "BaselineModerate" INTEGER;
ALTER TABLE "CONTROL" ADD COLUMN "BaselineHigh" INTEGER;
ALTER TABLE "CONTROL" ADD COLUMN "BaselinePrivacy" INTEGER;
ALTER TABLE "CONTROL" ADD COLUMN "Statement" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "Guidance" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "Params" TEXT;
ALTER TABLE "CONTROL" ADD COLUMN "RelatedControls" TEXT;
-- Per-tenant implementation status + SP 800-53A assessment of an 800-53 control (one per control per tenant).
CREATE TABLE IF NOT EXISTS "CONTROLIMPLEMENTATION" (
  "ControlImplementationID" INTEGER PRIMARY KEY,
  "ControlImplementationGUID" TEXT,
  "ControlID" INTEGER,
  "Status" TEXT,
  "Responsibility" TEXT,
  "Narrative" TEXT,
  "OwnerPersonID" INTEGER,
  "TargetDate" DATE,
  "LastReviewedDate" TEXT,
  "AssessmentResult" TEXT,
  "AssessedDate" TEXT,
  "AssessorPersonID" INTEGER,
  "AssessmentRemarks" TEXT,
  "CreatedDate" TEXT,
  "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_ctrlimpl_control ON "CONTROLIMPLEMENTATION"("ControlID");
CREATE INDEX IF NOT EXISTS ix_ctrlimpl_tenant ON "CONTROLIMPLEMENTATION"("TenantID");
-- Crosswalk: an 800-53 control mapped to another framework object (ATT&CK technique, D3FEND, CSF…).
-- Global reference facts, filled by import_attack_80053_mappings.py.
CREATE TABLE IF NOT EXISTS "CONTROLMAPPING" (
  "MappingID" INTEGER PRIMARY KEY,
  "MappingGUID" TEXT,
  "ControlID" INTEGER,
  "Framework" TEXT,
  "ExternalID" TEXT,
  "ExternalName" TEXT,
  "Relationship" TEXT,
  "Source" TEXT,
  "CreatedDate" TEXT);
CREATE INDEX IF NOT EXISTS ix_ctrlmap_control ON "CONTROLMAPPING"("ControlID");
CREATE INDEX IF NOT EXISTS ix_ctrlmap_fw ON "CONTROLMAPPING"("Framework");
-- Plan of Action & Milestones — a control deficiency tracked to closure (per tenant).
CREATE TABLE IF NOT EXISTS "CONTROLPOAM" (
  "PoamID" INTEGER PRIMARY KEY,
  "PoamGUID" TEXT,
  "ControlID" INTEGER,
  "Title" TEXT,
  "WeaknessDescription" TEXT,
  "Severity" TEXT,
  "Status" TEXT,
  "RemediationPlan" TEXT,
  "Milestones" TEXT,
  "OwnerPersonID" INTEGER,
  "ScheduledCompletionDate" DATE,
  "ActualCompletionDate" DATE,
  "CreatedDate" TEXT,
  "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_ctrlpoam_control ON "CONTROLPOAM"("ControlID");
CREATE INDEX IF NOT EXISTS ix_ctrlpoam_tenant ON "CONTROLPOAM"("TenantID");

-- Backup/restore TEST log against a BACKUPPLAN (manage backup testing: restore / integrity / failover).
CREATE TABLE IF NOT EXISTS "BACKUPTEST" (
  "BackupTestID" INTEGER PRIMARY KEY,
  "BackupTestGUID" TEXT,
  "BackupPlanID" INTEGER,
  "AssetID" INTEGER,
  "TestDate" DATE,
  "TestType" TEXT,
  "Result" TEXT,
  "RTOAchievedHours" REAL,
  "RPOAchievedHours" REAL,
  "DataIntegrityVerified" INTEGER,
  "TestedByPersonID" INTEGER,
  "Findings" TEXT,
  "NextTestDue" DATE,
  "Notes" TEXT,
  "CreatedDate" DATE,
  "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_backuptest_plan ON "BACKUPTEST"("BackupPlanID");
CREATE INDEX IF NOT EXISTS ix_backuptest_tenant ON "BACKUPTEST"("TenantID");

-- Adversary Opportunity Index (AOI) — STOCK/FLOW snapshot history + the item-level debt ledger.
CREATE TABLE IF NOT EXISTS "THREATDEBTSNAPSHOT" (
  "SnapshotID" INTEGER PRIMARY KEY,
  "TenantID" INTEGER,
  "CreatedDate" TEXT,
  "AOI" INTEGER,
  "RawDebt" REAL,
  "Paths" INTEGER);
CREATE TABLE IF NOT EXISTS "THREATDEBTLEDGER" (
  "LedgerID" INTEGER PRIMARY KEY,
  "TenantID" INTEGER,
  "ItemKey" TEXT,
  "Source" TEXT,
  "Label" TEXT,
  "Debt" REAL,
  "OpenedDate" TEXT,
  "LastSeenDate" TEXT,
  "ClosedDate" TEXT,
  "CtemExposureID" INTEGER);
CREATE INDEX IF NOT EXISTS IX_TDLEDGER_OPEN ON "THREATDEBTLEDGER"("TenantID","ClosedDate");

-- Cyber Insurance Readiness — the tenant's policy record (carrier / limit / renewal).
CREATE TABLE IF NOT EXISTS "CYBERINSURANCEPOLICY" (
  "PolicyID" INTEGER PRIMARY KEY,
  "TenantID" INTEGER,
  "Carrier" TEXT,
  "PolicyNumber" TEXT,
  "CoverageLimit" REAL,
  "Retention" REAL,
  "Premium" REAL,
  "Currency" TEXT,
  "RenewalDate" TEXT,
  "Status" TEXT,
  "Notes" TEXT,
  "CreatedDate" TEXT,
  "UpdatedDate" TEXT);

-- AI runtime anomaly detection — per-AISYSTEM usage telemetry (daily rollups) + detections.
CREATE TABLE IF NOT EXISTS "AIUSAGE" (
  "UsageID" INTEGER PRIMARY KEY, "AISystemID" INTEGER, "TenantID" INTEGER, "Day" TEXT,
  "Requests" INTEGER, "TokensIn" INTEGER, "TokensOut" INTEGER, "Refusals" INTEGER,
  "InjectionAttempts" INTEGER, "DistinctUsers" INTEGER, "CreatedDate" TEXT);
CREATE INDEX IF NOT EXISTS ix_aiusage_sys ON "AIUSAGE"("AISystemID","Day");
CREATE TABLE IF NOT EXISTS "AIDETECTION" (
  "DetectionID" INTEGER PRIMARY KEY, "AISystemID" INTEGER, "TenantID" INTEGER, "Day" TEXT,
  "Type" TEXT, "Severity" TEXT, "Detail" TEXT, "Evidence" TEXT, "Status" TEXT DEFAULT 'open', "CreatedDate" TEXT);
CREATE INDEX IF NOT EXISTS ix_aidet_tenant ON "AIDETECTION"("TenantID");

-- SLSA supply-chain level tracker — per-artifact build-integrity attributes (computed level L0-L3).
CREATE TABLE IF NOT EXISTS "SLSAARTIFACT" (
  "ArtifactID" INTEGER PRIMARY KEY, "ArtifactGUID" TEXT, "ProjectName" TEXT, "Repo" TEXT, "BuildPlatform" TEXT,
  "ProvenanceGenerated" INTEGER DEFAULT 0, "ProvenanceSigned" INTEGER DEFAULT 0, "BuildHosted" INTEGER DEFAULT 0,
  "Isolated" INTEGER DEFAULT 0, "Hermetic" INTEGER DEFAULT 0, "TwoPersonReviewed" INTEGER DEFAULT 0,
  "ProvenanceVerified" INTEGER DEFAULT 0, "Notes" TEXT, "TenantID" INTEGER, "CreatedDate" TEXT);
CREATE INDEX IF NOT EXISTS ix_slsa_tenant ON "SLSAARTIFACT"("TenantID");

-- LLM Application Penetration Test methodology (llmpentest.ts): OWASP-LLM-2025 engagement + per-test-case tracker
CREATE TABLE IF NOT EXISTS "LLMPENTEST" (
  "EngagementID" INTEGER PRIMARY KEY, "EngagementGUID" TEXT, "AISystemID" INTEGER, "SystemName" TEXT,
  "Title" TEXT, "Scope" TEXT, "Tester" TEXT, "Status" TEXT, "Phase" INTEGER,
  "ReadinessScore" INTEGER, "Coverage" INTEGER, "Grade" TEXT, "Tested" INTEGER, "Passed" INTEGER, "Failed" INTEGER,
  "OpenFindings" INTEGER, "CreatedDate" TEXT, "UpdatedDate" TEXT, "TenantID" INTEGER);
CREATE TABLE IF NOT EXISTS "LLMPENTESTCASE" (
  "CaseID" INTEGER PRIMARY KEY, "EngagementID" INTEGER, "Owasp" TEXT, "Category" TEXT, "Mode" TEXT,
  "TestID" TEXT, "TestName" TEXT, "Technique" TEXT, "Status" TEXT, "Severity" TEXT, "Source" TEXT,
  "Finding" TEXT, "Evidence" TEXT, "CreatedDate" TEXT, "UpdatedDate" TEXT);
CREATE INDEX IF NOT EXISTS ix_llmpt_tenant ON "LLMPENTEST"("TenantID");
CREATE INDEX IF NOT EXISTS ix_llmpt_sys ON "LLMPENTEST"("AISystemID");
CREATE INDEX IF NOT EXISTS ix_llmptcase_eng ON "LLMPENTESTCASE"("EngagementID");

-- AI Operations (aiskills.ts): governed Skills/Prompt library + AI activity provenance log + agent handover routing
CREATE TABLE IF NOT EXISTS "AISKILL" (
  "SkillID" INTEGER PRIMARY KEY, "SkillGUID" TEXT, "Kind" TEXT, "Name" TEXT, "Description" TEXT, "Tags" TEXT,
  "Content" TEXT, "Source" TEXT, "Enabled" INTEGER DEFAULT 1, "Visibility" TEXT, "Version" INTEGER DEFAULT 1,
  "UsedCount" INTEGER DEFAULT 0, "Category" TEXT, "CreatedDate" TEXT, "UpdatedDate" TEXT, "TenantID" INTEGER);
CREATE TABLE IF NOT EXISTS "AIACTIVITY" (
  "ActivityID" INTEGER PRIMARY KEY, "ActivityGUID" TEXT, "Actor" TEXT, "Action" TEXT, "Model" TEXT, "Provider" TEXT,
  "SkillID" INTEGER, "EntityType" TEXT, "EntityKey" TEXT, "Summary" TEXT, "TokensIn" INTEGER, "TokensOut" INTEGER,
  "Outcome" TEXT, "CreatedDate" TEXT, "TenantID" INTEGER);
CREATE TABLE IF NOT EXISTS "AIHANDOVER" (
  "RouteID" INTEGER PRIMARY KEY, "RouteGUID" TEXT, "FromAgent" TEXT, "ToAgent" TEXT, "Type" TEXT, "Trigger" TEXT,
  "Enabled" INTEGER DEFAULT 1, "Notes" TEXT, "CreatedDate" TEXT, "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_aiskill_tenant ON "AISKILL"("TenantID");
CREATE INDEX IF NOT EXISTS ix_aiactivity_tenant ON "AIACTIVITY"("TenantID","ActivityID");
CREATE INDEX IF NOT EXISTS ix_aihandover_tenant ON "AIHANDOVER"("TenantID");

COMMIT;
