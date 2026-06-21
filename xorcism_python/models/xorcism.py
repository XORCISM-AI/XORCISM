"""
SQLAlchemy models for XORCISM database
Auto-generated from SQLite schema - replaces XORCISMModel/XORCISM C# POCO classes
"""
from sqlalchemy import Column, Integer, Float, String, Text, LargeBinary, Boolean
from .base import Base


class ACCESSEDDIRECTORYLIST(Base):
    __tablename__ = 'ACCESSEDDIRECTORYLIST'
    __bind_key__  = 'XORCISM'

    AccessedDirectoryListID = Column(Integer, nullable=False, primary_key=True)
    AccessedDirectoryListGUID = Column(Text)
    AccessedDirectoryListName = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)

    def __repr__(self):
        return f'<ACCESSEDDIRECTORYLIST {self.AccessedDirectoryListID}>'

class ACCESSEDFILELIST(Base):
    __tablename__ = 'ACCESSEDFILELIST'
    __bind_key__  = 'XORCISM'

    AccessedFileListID = Column(Integer, nullable=False, primary_key=True)
    AccessedFileListGUID = Column(Text)
    AccessedFileListName = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)

    def __repr__(self):
        return f'<ACCESSEDFILELIST {self.AccessedFileListID}>'

class ACCESSEDFILELISTFILES(Base):
    __tablename__ = 'ACCESSEDFILELISTFILES'
    __bind_key__  = 'XORCISM'

    AccessedFileListFileID = Column(Integer, nullable=False, primary_key=True)
    AccessedFileListFileGUID = Column(Text)
    AccessedFileListID = Column(Integer, nullable=False)
    AccessedFileListGUID = Column(Text)
    FileID = Column(Integer, nullable=False)
    FileGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ACCESSEDFILELISTFILES {self.AccessedFileListFileID}>'

class ACCESSRECORD(Base):
    __tablename__ = 'ACCESSRECORD'
    __bind_key__  = 'XORCISM'

    AccessRecordID = Column(Integer, nullable=False, primary_key=True)
    AccessRecordGUID = Column(Text)
    RecordGUID = Column(Text)
    UserID = Column(Integer)
    UserGUID = Column(Text)
    AccessType = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    isEncrypted = Column(Integer)
    CollectionMethodID = Column(Integer)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)
    AssetID = Column(Integer)

    def __repr__(self):
        return f'<ACCESSRECORD {self.AccessRecordID}>'

class ACCESSRECORDEVIDENCE(Base):
    __tablename__ = 'ACCESSRECORDEVIDENCE'
    __bind_key__  = 'XORCISM'

    AccessRecordEvidenceID = Column(Integer, nullable=False, primary_key=True)
    AccessRecordID = Column(Integer)
    AccessRecordGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACCESSRECORDEVIDENCE {self.AccessRecordEvidenceID}>'

class ACCESSRECORDHASH(Base):
    __tablename__ = 'ACCESSRECORDHASH'
    __bind_key__  = 'XORCISM'

    AccessRecordHashID = Column(Integer, nullable=False, primary_key=True)
    AccessRecordHashGUID = Column(Text)
    AccessRecordID = Column(Integer, nullable=False)
    HashValue = Column(Text, nullable=False)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)

    def __repr__(self):
        return f'<ACCESSRECORDHASH {self.AccessRecordHashID}>'

class ACCOUNT(Base):
    __tablename__ = 'ACCOUNT'
    __bind_key__  = 'XORCISM'

    AccountID = Column(Integer, nullable=False, primary_key=True)
    AccountGUID = Column(Text)
    AccountName = Column(Text)
    AccountDomain = Column(Text)
    DomainNameID = Column(Integer)
    DomainNameGUID = Column(Text)
    AccountDescription = Column(Text)
    Creation_Date = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    Modified_Date = Column(Text)
    BLOB = Column(Text)
    Last_Accessed_Time = Column(Text)
    disabled = Column(Integer)
    locked_out = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    OrganisationID = Column(Integer)
    OrganisationGUID = Column(Text)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<ACCOUNT {self.AccountID}>'

class ACCOUNTAUTHENTICATION(Base):
    __tablename__ = 'ACCOUNTAUTHENTICATION'
    __bind_key__  = 'XORCISM'

    AccountAuthenticationID = Column(Integer, nullable=False, primary_key=True)
    AccountAuthenticationGUID = Column(Text)
    AccountID = Column(Integer, nullable=False)
    AccountGUID = Column(Text)
    AuthenticationTypeID = Column(Integer, nullable=False)
    AuthenticationTypeGUID = Column(Text)
    Authentication_Data = Column(Text)
    isEncrypted = Column(Integer)
    Authentication_Token_Protection_Mechanism = Column(Text)
    AuthenticationTokenProtectionMechanismID = Column(Integer)
    AuthenticationTokenProtectionMechanismGUID = Column(Text)
    StructuredAuthenticationMechanismID = Column(Integer)
    StructuredAuthenticationMechanismGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ACCOUNTAUTHENTICATION {self.AccountAuthenticationID}>'

class ACCOUNTAUTHENTICATIONTYPE(Base):
    __tablename__ = 'ACCOUNTAUTHENTICATIONTYPE'
    __bind_key__  = 'XORCISM'

    AccountAuthenticationTypeID = Column(Integer, nullable=False, primary_key=True)
    AccountAuthenticationTypeGUID = Column(Text)
    AccountID = Column(Integer, nullable=False)
    AccountGUID = Column(Text)
    AuthenticationTypeID = Column(Integer, nullable=False)
    AuthenticationTypeGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACCOUNTAUTHENTICATIONTYPE {self.AccountAuthenticationTypeID}>'

class ACCOUNTBLACKLIST(Base):
    __tablename__ = 'ACCOUNTBLACKLIST'
    __bind_key__  = 'XORCISM'

    AccountBlacklistID = Column(Integer, nullable=False, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACCOUNTBLACKLIST {self.AccountBlacklistID}>'

class ACCOUNTCHANGERECORD(Base):
    __tablename__ = 'ACCOUNTCHANGERECORD'
    __bind_key__  = 'XORCISM'

    AccountChangeRecordID = Column(Integer, nullable=False, primary_key=True)
    AccountChangeRecordGUID = Column(Text)
    AccountID = Column(Integer, nullable=False)
    AccountGUID = Column(Text)
    ChangeRecordID = Column(Integer, nullable=False)
    ChangeRecordGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACCOUNTCHANGERECORD {self.AccountChangeRecordID}>'

class ACCOUNTDESCRIPTION(Base):
    __tablename__ = 'ACCOUNTDESCRIPTION'
    __bind_key__  = 'XORCISM'

    AccountDescriptionID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ACCOUNTDESCRIPTION {self.AccountDescriptionID}>'

class ACCOUNTTYPE(Base):
    __tablename__ = 'ACCOUNTTYPE'
    __bind_key__  = 'XORCISM'

    AccountTypeID = Column(Integer, nullable=False, primary_key=True)
    AccountTypeName = Column(Text)
    AccountTypeDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ACCOUNTTYPE {self.AccountTypeID}>'

class ACCOUNTWHITELIST(Base):
    __tablename__ = 'ACCOUNTWHITELIST'
    __bind_key__  = 'XORCISM'

    AccountWhitelistID = Column(Integer, nullable=False, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACCOUNTWHITELIST {self.AccountWhitelistID}>'

class ACE(Base):
    __tablename__ = 'ACE'
    __bind_key__  = 'XORCISM'

    ACEID = Column(Integer, nullable=False, primary_key=True)
    ACEGUID = Column(Text)

    def __repr__(self):
        return f'<ACE {self.ACEID}>'

class ACL(Base):
    __tablename__ = 'ACL'
    __bind_key__  = 'XORCISM'

    ACLID = Column(Integer, nullable=False, primary_key=True)
    ACLGUID = Column(Text)

    def __repr__(self):
        return f'<ACL {self.ACLID}>'

class ACLENTRY(Base):
    __tablename__ = 'ACLENTRY'
    __bind_key__  = 'XORCISM'

    ACLEntryID = Column(Integer, nullable=False, primary_key=True)
    ACLEntryGUID = Column(Text)
    ACLID = Column(Integer)
    ACLGUID = Column(Text)
    ACEID = Column(Integer)
    ACEGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CreationObjectGUID = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACLENTRY {self.ACLEntryID}>'

class ACRONYM(Base):
    __tablename__ = 'ACRONYM'
    __bind_key__  = 'XORCISM'

    AcronymID = Column(Integer, nullable=False, primary_key=True)
    AcronymGUID = Column(Text)
    AcronymAbbreviation = Column(Text, nullable=False)
    AcronymPhrase = Column(Text, nullable=False)
    AcronymDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidityID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACRONYM {self.AcronymID}>'

class ACTION(Base):
    __tablename__ = 'ACTION'
    __bind_key__  = 'XORCISM'

    ActionID = Column(Integer, nullable=False, primary_key=True)
    ActionGUID = Column(Text)
    ActionName = Column(Text)
    ActionREFID = Column(Text)
    ActionStatusID = Column(Integer)
    ActionStatusName = Column(Text)
    ordinal_position = Column(Integer)
    ActionContextID = Column(Integer)
    ActionContextName = Column(Text)
    ActionTimestamp = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ActionDescription = Column(Text)
    isEncrypted = Column(Integer)
    isSuspicious = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ACTION {self.ActionID}>'

class ACTIONACTION(Base):
    __tablename__ = 'ACTIONACTION'
    __bind_key__  = 'XORCISM'

    ActionRelationshipID = Column(Integer, nullable=False, primary_key=True)
    ActionRefID = Column(Integer, nullable=False)
    ActionRefGUID = Column(Text)
    ActionRelationshipTypeID = Column(Integer, nullable=False)
    ActionRelationshipTypeName = Column(Text, nullable=False)
    ActionSubjectID = Column(Integer, nullable=False)
    ActionSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONACTION {self.ActionRelationshipID}>'

class ACTIONACTIONARGUMENTNAME(Base):
    __tablename__ = 'ACTIONACTIONARGUMENTNAME'
    __bind_key__  = 'XORCISM'

    ActionActionArgumentNameID = Column(Integer, nullable=False, primary_key=True)
    ActionID = Column(Integer, nullable=False)
    ActionGUID = Column(Text)
    ActionArgumentNameID = Column(Integer, nullable=False)
    ActionArgumentNameGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACTIONACTIONARGUMENTNAME {self.ActionActionArgumentNameID}>'

class ACTIONACTIONNAME(Base):
    __tablename__ = 'ACTIONACTIONNAME'
    __bind_key__  = 'XORCISM'

    ActionActionNameID = Column(Integer, nullable=False, primary_key=True)
    ActionID = Column(Integer, nullable=False)
    ActionGUID = Column(Text)
    ActionNameID = Column(Integer, nullable=False)
    ActionNameGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACTIONACTIONNAME {self.ActionActionNameID}>'

class ACTIONACTIONTYPE(Base):
    __tablename__ = 'ACTIONACTIONTYPE'
    __bind_key__  = 'XORCISM'

    ActionActionTypeID = Column(Integer, nullable=False, primary_key=True)
    ActionID = Column(Integer, nullable=False)
    ActionGUID = Column(Text)
    ActionTypeID = Column(Integer, nullable=False)
    ActionTypeGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACTIONACTIONTYPE {self.ActionActionTypeID}>'

class ACTIONALIAS(Base):
    __tablename__ = 'ACTIONALIAS'
    __bind_key__  = 'XORCISM'

    ActionAliasID = Column(Integer, nullable=False, primary_key=True)
    ActionID = Column(Integer, nullable=False)
    ActionGUID = Column(Text)
    ActionAlias = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ACTIONALIAS {self.ActionAliasID}>'

class ACTIONARGUMENTNAME(Base):
    __tablename__ = 'ACTIONARGUMENTNAME'
    __bind_key__  = 'XORCISM'

    ActionArgumentNameID = Column(Integer, nullable=False, primary_key=True)
    ActionArgumentNameGUID = Column(Text)
    ActionArgumentNameName = Column(Text, nullable=False)
    ActionArgumentNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONARGUMENTNAME {self.ActionArgumentNameID}>'

class ACTIONASSOCIATION(Base):
    __tablename__ = 'ACTIONASSOCIATION'
    __bind_key__  = 'XORCISM'

    ActionAssociationID = Column(Integer, nullable=False, primary_key=True)
    ActionObjectAssociationType = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ACTIONASSOCIATION {self.ActionAssociationID}>'

class ACTIONCOLLECTION(Base):
    __tablename__ = 'ACTIONCOLLECTION'
    __bind_key__  = 'XORCISM'

    ActionCollectionID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ACTIONCOLLECTION {self.ActionCollectionID}>'

class ACTIONCONTEXT(Base):
    __tablename__ = 'ACTIONCONTEXT'
    __bind_key__  = 'XORCISM'

    ActionContextID = Column(Integer, primary_key=True)
    ActionContextGUID = Column(Text)
    ActionContextName = Column(Text, nullable=False)
    ActionContextDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACTIONCONTEXT {self.ActionContextID}>'

class ACTIONDESCRIPTION(Base):
    __tablename__ = 'ACTIONDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ActionDescriptionID = Column(Integer, nullable=False, primary_key=True)
    ActionID = Column(Integer, nullable=False)
    ActionGUID = Column(Text)
    DescriptionID = Column(Integer, nullable=False)
    DescriptionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ACTIONDESCRIPTION {self.ActionDescriptionID}>'

class ACTIONDISCOVERYMETHOD(Base):
    __tablename__ = 'ACTIONDISCOVERYMETHOD'
    __bind_key__  = 'XORCISM'

    ActionDiscoveryMethodID = Column(Integer, nullable=False, primary_key=True)
    ActionID = Column(Integer, nullable=False)
    ActionGUID = Column(Text)
    DiscoveryMethodID = Column(Integer, nullable=False)
    DiscoveryMethodGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ACTIONDISCOVERYMETHOD {self.ActionDiscoveryMethodID}>'

class ACTIONIMPLEMENTATION(Base):
    __tablename__ = 'ACTIONIMPLEMENTATION'
    __bind_key__  = 'XORCISM'

    ActionImplementationID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ACTIONIMPLEMENTATION {self.ActionImplementationID}>'

class ACTIONNAME(Base):
    __tablename__ = 'ACTIONNAME'
    __bind_key__  = 'XORCISM'

    ActionNameID = Column(Integer, nullable=False, primary_key=True)
    ActionNameName = Column(Text, nullable=False)
    ActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONNAME {self.ActionNameID}>'

class ACTIONOBJECTASSOCIATIONTYPE(Base):
    __tablename__ = 'ACTIONOBJECTASSOCIATIONTYPE'
    __bind_key__  = 'XORCISM'

    ActionObjectAssociationTypeID = Column(Integer, nullable=False, primary_key=True)
    ActionObjectAssociationTypeName = Column(Text, nullable=False)
    ActionObjectAssociationTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONOBJECTASSOCIATIONTYPE {self.ActionObjectAssociationTypeID}>'

class ACTIONPLAN(Base):
    __tablename__ = 'ACTIONPLAN'
    __bind_key__  = 'XORCISM'

    ActionPlanID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ACTIONPLAN {self.ActionPlanID}>'

class ACTIONPOOL(Base):
    __tablename__ = 'ACTIONPOOL'
    __bind_key__  = 'XORCISM'

    ActionPoolID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ACTIONPOOL {self.ActionPoolID}>'

class ACTIONRELATIONSHIPTYPE(Base):
    __tablename__ = 'ACTIONRELATIONSHIPTYPE'
    __bind_key__  = 'XORCISM'

    ActionRelationshipTypeID = Column(Integer, nullable=False, primary_key=True)
    ActionRelationshipTypeName = Column(Text, nullable=False)
    ActionRelationshipTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONRELATIONSHIPTYPE {self.ActionRelationshipTypeID}>'

class ACTIONSTATUS(Base):
    __tablename__ = 'ACTIONSTATUS'
    __bind_key__  = 'XORCISM'

    ActionStatusID = Column(Integer, nullable=False, primary_key=True)
    ActionStatusName = Column(Text, nullable=False)
    ActionStatusDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONSTATUS {self.ActionStatusID}>'

class ACTIONTAKEN(Base):
    __tablename__ = 'ACTIONTAKEN'
    __bind_key__  = 'XORCISM'

    ActionTakenID = Column(Integer, nullable=False, primary_key=True)
    ActionTakenGUID = Column(Text)
    ActionName = Column(Text, nullable=False)
    ActionDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACTIONTAKEN {self.ActionTakenID}>'

class ACTIONTAKENFORINCIDENT(Base):
    __tablename__ = 'ACTIONTAKENFORINCIDENT'
    __bind_key__  = 'XORCISM'

    ActionTakenForIncidentID = Column(Integer, nullable=False, primary_key=True)
    ActionTakenID = Column(Integer, nullable=False)
    IncidentID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    CreationObjectID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONTAKENFORINCIDENT {self.ActionTakenForIncidentID}>'

class ACTIONTAKENFORTHREATCAMPAIGN(Base):
    __tablename__ = 'ACTIONTAKENFORTHREATCAMPAIGN'
    __bind_key__  = 'XORCISM'

    ActionTakenForThreatCampaignID = Column(Integer, nullable=False, primary_key=True)
    ActionTakenID = Column(Integer, nullable=False)
    ThreatCampaignID = Column(Integer, nullable=False)
    ThreatActorID = Column(Integer)
    ActionStartDate = Column(Text)
    ActionEndDate = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    CreationObjectID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONTAKENFORTHREATCAMPAIGN {self.ActionTakenForThreatCampaignID}>'

class ACTIONTYPE(Base):
    __tablename__ = 'ACTIONTYPE'
    __bind_key__  = 'XORCISM'

    ActionTypeID = Column(Integer, nullable=False, primary_key=True)
    ActionTypeGUID = Column(Text)
    ActionTypeName = Column(Text, nullable=False)
    ActionTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ACTIONTYPE {self.ActionTypeID}>'

class ACTIVATIONFUNCTION(Base):
    __tablename__ = 'ACTIVATIONFUNCTION'
    __bind_key__  = 'XORCISM'

    ActivationFunctionID = Column(Integer, nullable=False, primary_key=True)
    FunctionID = Column(Integer)

    def __repr__(self):
        return f'<ACTIVATIONFUNCTION {self.ActivationFunctionID}>'

class ACTIVATIONZONE(Base):
    __tablename__ = 'ACTIVATIONZONE'
    __bind_key__  = 'XORCISM'

    ActivationZoneID = Column(Integer, nullable=False, primary_key=True)
    ActivationZoneGUID = Column(Text)
    ActivationZoneText = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ACTIVATIONZONE {self.ActivationZoneID}>'

class ACTIVATIONZONEFORATTACKPATTERN(Base):
    __tablename__ = 'ACTIVATIONZONEFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternActivationZoneID = Column(Integer, nullable=False, primary_key=True)
    AttackPatternActivationZoneGUID = Column(Text)
    ActivationZoneID = Column(Integer, nullable=False)
    ActivationZoneGUID = Column(Text)
    AttackPatternID = Column(Integer, nullable=False)
    AttackPatternGUID = Column(Text)
    capec_id = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ACTIVATIONZONEFORATTACKPATTERN {self.AttackPatternActivationZoneID}>'

class ADDRESS(Base):
    __tablename__ = 'ADDRESS'
    __bind_key__  = 'XORCISM'

    AddressID = Column(Integer, nullable=False, primary_key=True)
    AddressGUID = Column(Text)
    CategoryID = Column(Integer)
    AddressCategoryID = Column(Integer)
    category = Column(Text)
    Address_Value = Column(Text)
    VLAN_Name = Column(Text)
    VLAN_Num = Column(Integer)
    is_source = Column(Integer)
    is_destination = Column(Integer)
    is_spoofed = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<ADDRESS {self.AddressID}>'

class ADDRESSBLACKLIST(Base):
    __tablename__ = 'ADDRESSBLACKLIST'
    __bind_key__  = 'XORCISM'

    AddressBlacklistID = Column(Integer, nullable=False, primary_key=True)
    AddressID = Column(Integer)
    EmailID = Column(Integer)
    emailaddress = Column(Text)
    is_source = Column(Integer)
    is_destination = Column(Integer)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)
    AssetID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ADDRESSBLACKLIST {self.AddressBlacklistID}>'

class ADDRESSCATEGORY(Base):
    __tablename__ = 'ADDRESSCATEGORY'
    __bind_key__  = 'XORCISM'

    AddressCategoryID = Column(Integer, nullable=False, primary_key=True)
    AddressCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    AddressCategoryName = Column(Text)
    AddressCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ADDRESSCATEGORY {self.AddressCategoryID}>'

class ADDRESSCOUNTRY(Base):
    __tablename__ = 'ADDRESSCOUNTRY'
    __bind_key__  = 'XORCISM'

    AddressCountryID = Column(Integer, nullable=False, primary_key=True)
    AddressID = Column(Integer)
    AddressGUID = Column(Text)
    CountryID = Column(Integer)
    CountryGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ADDRESSCOUNTRY {self.AddressCountryID}>'

class ADDRESSREPUTATION(Base):
    __tablename__ = 'ADDRESSREPUTATION'
    __bind_key__  = 'XORCISM'

    AddressReputationID = Column(Integer, nullable=False, primary_key=True)
    AddressID = Column(Integer)
    AddressGUID = Column(Text)
    ReputationID = Column(Integer)
    ReputationGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ADDRESSREPUTATION {self.AddressReputationID}>'

class ADDRESSWHITELIST(Base):
    __tablename__ = 'ADDRESSWHITELIST'
    __bind_key__  = 'XORCISM'

    AddressWhitelistID = Column(Integer, nullable=False, primary_key=True)
    AddressID = Column(Integer)
    EmailID = Column(Integer)
    emailaddress = Column(Text)
    is_source = Column(Integer)
    is_destination = Column(Integer)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)
    AssetID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ADDRESSWHITELIST {self.AddressWhitelistID}>'

class ADVISORY(Base):
    __tablename__ = 'ADVISORY'
    __bind_key__  = 'XORCISM'

    AdvisoryID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ADVISORY {self.AdvisoryID}>'

class AFFECTEDRESOURCE(Base):
    __tablename__ = 'AFFECTEDRESOURCE'
    __bind_key__  = 'XORCISM'

    AffectedResourceID = Column(Integer, nullable=False, primary_key=True)
    AffectedResourceName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<AFFECTEDRESOURCE {self.AffectedResourceID}>'

class AGENT(Base):
    __tablename__ = 'AGENT'
    __bind_key__  = 'XORCISM'

    AgentID = Column(Integer, nullable=False, primary_key=True)
    AgentGUID = Column(Text)
    ipaddressIPv4 = Column(Text)
    AgentStatus = Column(Text)
    AgentLoadValue = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    SensorID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<AGENT {self.AgentID}>'

class ALGEBRAIC(Base):
    __tablename__ = 'ALGEBRAIC'
    __bind_key__  = 'XORCISM'

    AlgebraicID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ALGEBRAIC {self.AlgebraicID}>'

class ALGORITHM(Base):
    __tablename__ = 'ALGORITHM'
    __bind_key__  = 'XORCISM'

    AlgorithmID = Column(Integer, nullable=False, primary_key=True)
    AlgorithmName = Column(Text)
    AlgorithmVersion = Column(Text)
    AlgorithmVersionID = Column(Integer)
    AlgorithmDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ALGORITHM {self.AlgorithmID}>'

class ALGORITHMDESCRIPTION(Base):
    __tablename__ = 'ALGORITHMDESCRIPTION'
    __bind_key__  = 'XORCISM'

    AlgorithmDescriptionID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ALGORITHMDESCRIPTION {self.AlgorithmDescriptionID}>'

class ALGORITHMREFERENCE(Base):
    __tablename__ = 'ALGORITHMREFERENCE'
    __bind_key__  = 'XORCISM'

    AlgorithmReferenceID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ALGORITHMREFERENCE {self.AlgorithmReferenceID}>'

class ALGORITHMTAG(Base):
    __tablename__ = 'ALGORITHMTAG'
    __bind_key__  = 'XORCISM'

    AlgorithmTagID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<ALGORITHMTAG {self.AlgorithmTagID}>'

class ANTIBEHAVIORALANALYSISSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'ANTIBEHAVIORALANALYSISSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AntiBehavioralAnalysisStrategicObjectiveID = Column(Integer, nullable=False, primary_key=True)
    AntiBehavioralAnalysisStrategicObjectiveName = Column(Text)
    AntiBehavioralAnalysisStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ANTIBEHAVIORALANALYSISSTRATEGICOBJECTIVE {self.AntiBehavioralAnalysisStrategicObjectiveID}>'

class ANTIBEHAVIORALANALYSISTACTICALOBJECTIVE(Base):
    __tablename__ = 'ANTIBEHAVIORALANALYSISTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AntiBehavioralAnalysisTacticalObjectiveID = Column(Integer, nullable=False, primary_key=True)
    AntiBehavioralAnalysisTacticalObjectiveName = Column(Text)
    AntiBehavioralAnalysisTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ANTIBEHAVIORALANALYSISTACTICALOBJECTIVE {self.AntiBehavioralAnalysisTacticalObjectiveID}>'

class ANTIBEHAVIORANALYSISPROPERTIES(Base):
    __tablename__ = 'ANTIBEHAVIORANALYSISPROPERTIES'
    __bind_key__  = 'XORCISM'

    AntiBehavioralAnalysisPropertiesID = Column(Integer, nullable=False, primary_key=True)
    AntiBehavioralAnalysisPropertiesName = Column(Text)
    AntiBehavioralAnalysisPropertiesDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ANTIBEHAVIORANALYSISPROPERTIES {self.AntiBehavioralAnalysisPropertiesID}>'

class ANTICODEANALYSISSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'ANTICODEANALYSISSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AntiCodeAnalysisStrategicObjectiveID = Column(Integer, nullable=False, primary_key=True)
    AntiCodeAnalysisStrategicObjectiveName = Column(Text)
    AntiCodeAnalysisStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ANTICODEANALYSISSTRATEGICOBJECTIVE {self.AntiCodeAnalysisStrategicObjectiveID}>'

class ANTICODEANALYSISTACTICALOBJECTIVE(Base):
    __tablename__ = 'ANTICODEANALYSISTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AntiCodeAnalysisTacticalObjectiveID = Column(Integer, nullable=False, primary_key=True)
    AntiCodeAnalysisTacticalObjectiveName = Column(Text)
    AntiCodeAnalysisTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ANTICODEANALYSISTACTICALOBJECTIVE {self.AntiCodeAnalysisTacticalObjectiveID}>'

class ANTIDETECTIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'ANTIDETECTIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AntiDetectionStrategicObjectiveID = Column(Integer, nullable=False, primary_key=True)
    AntiDetectionStrategicObjectiveName = Column(Text)
    AntiDetectionStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ANTIDETECTIONSTRATEGICOBJECTIVE {self.AntiDetectionStrategicObjectiveID}>'

class ANTIDETECTIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'ANTIDETECTIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AntiDetectionTacticalObjectiveID = Column(Integer, nullable=False, primary_key=True)
    AntiDetectionTacticalObjectiveName = Column(Text)
    AntiDetectionTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ANTIDETECTIONTACTICALOBJECTIVE {self.AntiDetectionTacticalObjectiveID}>'

class ANTIREMOVALSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'ANTIREMOVALSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AntiRemovalStrategicObjectiveID = Column(Integer, nullable=False, primary_key=True)
    AntiRemovalStrategicObjectiveName = Column(Text)
    AntiRemovalStrategicObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ANTIREMOVALSTRATEGICOBJECTIVE {self.AntiRemovalStrategicObjectiveID}>'

class ANTIREMOVALTACTICALOBJECTIVE(Base):
    __tablename__ = 'ANTIREMOVALTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AntiRemovalTacticalObjectiveID = Column(Integer, nullable=False, primary_key=True)
    AntiRemovalTacticalObjectiveName = Column(Text)
    AntiRemovalTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ANTIREMOVALTACTICALOBJECTIVE {self.AntiRemovalTacticalObjectiveID}>'

class API(Base):
    __tablename__ = 'API'
    __bind_key__  = 'XORCISM'

    APIID = Column(Integer, nullable=False, primary_key=True)
    APIGUID = Column(Text)
    APIName = Column(Text)
    APIDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<API {self.APIID}>'

class APICALL(Base):
    __tablename__ = 'APICALL'
    __bind_key__  = 'XORCISM'

    APICallID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<APICALL {self.APICallID}>'

class APIFUNCTION(Base):
    __tablename__ = 'APIFUNCTION'
    __bind_key__  = 'XORCISM'

    APIFunctionID = Column(Integer, nullable=False, primary_key=True)
    APIFunctionGUID = Column(Text)
    APIID = Column(Integer, nullable=False)
    FunctionID = Column(Integer, nullable=False)
    Function_Name = Column(Text)
    Normalized_Function_Name = Column(Text)
    Address = Column(Text)
    VocabularyID = Column(Integer)
    APIFunctionDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<APIFUNCTION {self.APIFunctionID}>'

class APIMEMORYADDRESS(Base):
    __tablename__ = 'APIMEMORYADDRESS'
    __bind_key__  = 'XORCISM'

    APIMemoryAddressID = Column(Integer, nullable=False, primary_key=True)
    APIID = Column(Integer, nullable=False)
    MemoryAddressID = Column(Integer, nullable=False)
    FunctionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<APIMEMORYADDRESS {self.APIMemoryAddressID}>'

class APIPLATFORM(Base):
    __tablename__ = 'APIPLATFORM'
    __bind_key__  = 'XORCISM'

    APIPlatformID = Column(Integer, nullable=False, primary_key=True)
    APIID = Column(Integer, nullable=False)
    PlatformID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APIPLATFORM {self.APIPlatformID}>'

class APPLICATION(Base):
    __tablename__ = 'APPLICATION'
    __bind_key__  = 'XORCISM'

    ApplicationID = Column(Integer, nullable=False, primary_key=True)
    ApplicationGUID = Column(Text)
    ApplicationName = Column(Text, nullable=False)
    ApplicationDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATION {self.ApplicationID}>'

class APPLICATIONAUTHENTICATIONTYPE(Base):
    __tablename__ = 'APPLICATIONAUTHENTICATIONTYPE'
    __bind_key__  = 'XORCISM'

    ApplicationAuthenticationTypeID = Column(Integer, nullable=False, primary_key=True)
    ApplicationID = Column(Integer)
    ApplicationGUID = Column(Text)
    AuthenticationTypeID = Column(Integer)
    AuthenticationTypeGUID = Column(Text)
    AuthenticationRank = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ApplicationAuthenticationTypeDescription = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONAUTHENTICATIONTYPE {self.ApplicationAuthenticationTypeID}>'

class APPLICATIONBLACKLIST(Base):
    __tablename__ = 'APPLICATIONBLACKLIST'
    __bind_key__  = 'XORCISM'

    ApplicationBlacklistID = Column(Integer, nullable=False, primary_key=True)

    def __repr__(self):
        return f'<APPLICATIONBLACKLIST {self.ApplicationBlacklistID}>'

class APPLICATIONCATEGORIES(Base):
    __tablename__ = 'APPLICATIONCATEGORIES'
    __bind_key__  = 'XORCISM'

    ApplicationCategoriesID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    ApplicationCategoryID = Column(Integer, nullable=False)
    ApplicationCategoryGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONCATEGORIES {self.ApplicationCategoriesID}>'

class APPLICATIONCATEGORY(Base):
    __tablename__ = 'APPLICATIONCATEGORY'
    __bind_key__  = 'XORCISM'

    ApplicationCategoryID = Column(Integer, primary_key=True)
    ApplicationCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    ApplicationCategoryName = Column(Text)
    ApplicationCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONCATEGORY {self.ApplicationCategoryID}>'

class APPLICATIONCRITICALITY(Base):
    __tablename__ = 'APPLICATIONCRITICALITY'
    __bind_key__  = 'XORCISM'

    ApplicationCriticalityID = Column(Integer, primary_key=True)
    ApplicationCriticalityDescription = Column(Text)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    ApplicationCriticalityLevelID = Column(Integer, nullable=False)
    ApplicationCriticalityLevelGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONCRITICALITY {self.ApplicationCriticalityID}>'

class APPLICATIONCRITICALITYLEVEL(Base):
    __tablename__ = 'APPLICATIONCRITICALITYLEVEL'
    __bind_key__  = 'XORCISM'

    ApplicationCriticalityLevelID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<APPLICATIONCRITICALITYLEVEL {self.ApplicationCriticalityLevelID}>'

class APPLICATIONDEPENDENCY(Base):
    __tablename__ = 'APPLICATIONDEPENDENCY'
    __bind_key__  = 'XORCISM'

    ApplicationDependencyID = Column(Integer, primary_key=True)
    ApplicationParentID = Column(Integer)
    ApplicationParentGUID = Column(Text)
    ApplicationSubjectID = Column(Integer)
    ApplicationSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONDEPENDENCY {self.ApplicationDependencyID}>'

class APPLICATIONDOCUMENT(Base):
    __tablename__ = 'APPLICATIONDOCUMENT'
    __bind_key__  = 'XORCISM'

    ApplicationDocumentID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer)
    ApplicationGUID = Column(Text)
    DocumentID = Column(Integer)
    DocumentGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONDOCUMENT {self.ApplicationDocumentID}>'

class APPLICATIONFILEEXTENSIONBLACKLIST(Base):
    __tablename__ = 'APPLICATIONFILEEXTENSIONBLACKLIST'
    __bind_key__  = 'XORCISM'

    ApplicationFileExtensionBlacklistID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<APPLICATIONFILEEXTENSIONBLACKLIST {self.ApplicationFileExtensionBlacklistID}>'

class APPLICATIONFILEEXTENSIONWHITELIST(Base):
    __tablename__ = 'APPLICATIONFILEEXTENSIONWHITELIST'
    __bind_key__  = 'XORCISM'

    ApplicationFileExtensionWhitelistID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<APPLICATIONFILEEXTENSIONWHITELIST {self.ApplicationFileExtensionWhitelistID}>'

class APPLICATIONFILELIST(Base):
    __tablename__ = 'APPLICATIONFILELIST'
    __bind_key__  = 'XORCISM'

    ApplicationFileListID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer)
    ApplicationGUID = Column(Text)
    ApplicationFileListRelationship = Column(Text)
    ApplicationFileListDescription = Column(Text)
    FileListID = Column(Integer)
    FileListGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONFILELIST {self.ApplicationFileListID}>'

class APPLICATIONFORASSET(Base):
    __tablename__ = 'APPLICATIONFORASSET'
    __bind_key__  = 'XORCISM'

    AssetApplicationID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<APPLICATIONFORASSET {self.AssetApplicationID}>'

class APPLICATIONFORORGANISATION(Base):
    __tablename__ = 'APPLICATIONFORORGANISATION'
    __bind_key__  = 'XORCISM'

    OrganisationApplicationID = Column(Integer, primary_key=True)
    OrganisationApplicationGUID = Column(Text)
    OrganisationID = Column(Integer, nullable=False)
    OrganisationGUID = Column(Text)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<APPLICATIONFORORGANISATION {self.OrganisationApplicationID}>'

class APPLICATIONFUNCTION(Base):
    __tablename__ = 'APPLICATIONFUNCTION'
    __bind_key__  = 'XORCISM'

    ApplicationFunctionID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    FunctionID = Column(Integer, nullable=False)
    FunctionGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONFUNCTION {self.ApplicationFunctionID}>'

class APPLICATIONMIMEWHITELIST(Base):
    __tablename__ = 'APPLICATIONMIMEWHITELIST'
    __bind_key__  = 'XORCISM'

    ApplicationMIMEWhitelistID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    MIMEWhitelistID = Column(Integer, nullable=False)
    MIMEWhitelistGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONMIMEWHITELIST {self.ApplicationMIMEWhitelistID}>'

class APPLICATIONNETWORKZONE(Base):
    __tablename__ = 'APPLICATIONNETWORKZONE'
    __bind_key__  = 'XORCISM'

    NetworkZoneApplicationID = Column(Integer, primary_key=True)
    NetworkZoneID = Column(Integer)
    NetworkZoneGUID = Column(Text)
    ApplicationID = Column(Integer)
    ApplicationGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONNETWORKZONE {self.NetworkZoneApplicationID}>'

class APPLICATIONPERSON(Base):
    __tablename__ = 'APPLICATIONPERSON'
    __bind_key__  = 'XORCISM'

    ApplicationPersonID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    PersonID = Column(Integer, nullable=False)
    PersonGUID = Column(Text)
    Usage = Column(Text)
    Description = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONPERSON {self.ApplicationPersonID}>'

class APPLICATIONPORTWHITELIST(Base):
    __tablename__ = 'APPLICATIONPORTWHITELIST'
    __bind_key__  = 'XORCISM'

    ApplicationPortWhitelistID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer)
    ApplicationGUID = Column(Text)
    PortID = Column(Integer)
    inboundaccepted = Column(Integer)
    outboundaccepted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONPORTWHITELIST {self.ApplicationPortWhitelistID}>'

class APPLICATIONSECURITYLABEL(Base):
    __tablename__ = 'APPLICATIONSECURITYLABEL'
    __bind_key__  = 'XORCISM'

    ApplicationSecurityLabelID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    SecurityLabelID = Column(Integer, nullable=False)
    SecurityLabelGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONSECURITYLABEL {self.ApplicationSecurityLabelID}>'

class APPLICATIONURI(Base):
    __tablename__ = 'APPLICATIONURI'
    __bind_key__  = 'XORCISM'

    ApplicationURIID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    URIObjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONURI {self.ApplicationURIID}>'

class APPLICATIONURIWHITELIST(Base):
    __tablename__ = 'APPLICATIONURIWHITELIST'
    __bind_key__  = 'XORCISM'

    ApplicationURIWhitelistID = Column(Integer, primary_key=True)
    ApplicationURIID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ValidityID = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONURIWHITELIST {self.ApplicationURIWhitelistID}>'

class APPLICATIONVERSION(Base):
    __tablename__ = 'APPLICATIONVERSION'
    __bind_key__  = 'XORCISM'

    ApplicationVersionID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer)
    ApplicationGUID = Column(Text)
    VersionID = Column(Integer)
    ApplicationVersionDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<APPLICATIONVERSION {self.ApplicationVersionID}>'

class APPLICATIONWHITELIST(Base):
    __tablename__ = 'APPLICATIONWHITELIST'
    __bind_key__  = 'XORCISM'

    ApplicationWhitelistID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<APPLICATIONWHITELIST {self.ApplicationWhitelistID}>'

class APPROBATION(Base):
    __tablename__ = 'APPROBATION'
    __bind_key__  = 'XORCISM'

    ApprobationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<APPROBATION {self.ApprobationID}>'

class APPROVAL(Base):
    __tablename__ = 'APPROVAL'
    __bind_key__  = 'XORCISM'

    ApprovalID = Column(Integer, primary_key=True)
    ApprobationID = Column(Integer)

    def __repr__(self):
        return f'<APPROVAL {self.ApprovalID}>'

class ARCHITECTURALPARADIGM(Base):
    __tablename__ = 'ARCHITECTURALPARADIGM'
    __bind_key__  = 'XORCISM'

    ArchitecturalParadigmID = Column(Integer, primary_key=True)
    ArchitecturalParadigmGUID = Column(Text)
    ArchitecturalParadigmName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ARCHITECTURALPARADIGM {self.ArchitecturalParadigmID}>'

class ARCHITECTURALPARADIGMFORTECHNICALCONTEXT(Base):
    __tablename__ = 'ARCHITECTURALPARADIGMFORTECHNICALCONTEXT'
    __bind_key__  = 'XORCISM'

    TechnicalContextArchitecturalParadigmID = Column(Integer, primary_key=True)
    ArchitecturalParadigmID = Column(Integer, nullable=False)
    TechnicalContextID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ARCHITECTURALPARADIGMFORTECHNICALCONTEXT {self.TechnicalContextArchitecturalParadigmID}>'

class ARCHIVEFILE(Base):
    __tablename__ = 'ARCHIVEFILE'
    __bind_key__  = 'XORCISM'

    ArchiveFileID = Column(Integer, primary_key=True)
    FileID = Column(Integer)
    ArchiveFileDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ARCHIVEFILE {self.ArchiveFileID}>'

class ARFASSET(Base):
    __tablename__ = 'ARFASSET'
    __bind_key__  = 'XORCISM'

    ARFAssetID = Column(Integer, primary_key=True)
    ARFAssetUID = Column(Text, nullable=False)
    AssetID = Column(Integer)
    ReferenceID = Column(Integer)

    def __repr__(self):
        return f'<ARFASSET {self.ARFAssetID}>'

class ARFASSETFORASSETS(Base):
    __tablename__ = 'ARFASSETFORASSETS'
    __bind_key__  = 'XORCISM'

    AssetsID = Column(Integer, primary_key=True)
    ARFAssetID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFASSETFORASSETS {self.AssetsID}>'

class ARFEXTENDEDINFO(Base):
    __tablename__ = 'ARFEXTENDEDINFO'
    __bind_key__  = 'XORCISM'

    ARFExtendedInfoID = Column(Integer, primary_key=True)
    ExtendedInfoNCName = Column(Text, nullable=False)

    def __repr__(self):
        return f'<ARFEXTENDEDINFO {self.ARFExtendedInfoID}>'

class ARFEXTENDEDINFOFORARFEXTENDEDINFOS(Base):
    __tablename__ = 'ARFEXTENDEDINFOFORARFEXTENDEDINFOS'
    __bind_key__  = 'XORCISM'

    ARFExtendedInfosID = Column(Integer, primary_key=True)
    ARFExtendedInfoID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFEXTENDEDINFOFORARFEXTENDEDINFOS {self.ARFExtendedInfosID}>'

class ARFEXTENDEDINFOS(Base):
    __tablename__ = 'ARFEXTENDEDINFOS'
    __bind_key__  = 'XORCISM'

    ARFExtendedInfosID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ARFEXTENDEDINFOS {self.ARFExtendedInfosID}>'

class ARFOBJECTREF(Base):
    __tablename__ = 'ARFOBJECTREF'
    __bind_key__  = 'XORCISM'

    ARFObjectRefID = Column(Integer, primary_key=True)
    ARFObjectRefUID = Column(Text, nullable=False)

    def __repr__(self):
        return f'<ARFOBJECTREF {self.ARFObjectRefID}>'

class ARFOBJECTREFARFASSET(Base):
    __tablename__ = 'ARFOBJECTREFARFASSET'
    __bind_key__  = 'XORCISM'

    ARFObjectRefID = Column(Integer, primary_key=True)
    ARFAssetID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFOBJECTREFARFASSET {self.ARFObjectRefID}>'

class ARFOBJECTREFREPORT(Base):
    __tablename__ = 'ARFOBJECTREFREPORT'
    __bind_key__  = 'XORCISM'

    ARFObjectRefID = Column(Integer, primary_key=True)
    ReportID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFOBJECTREFREPORT {self.ARFObjectRefID}>'

class ARFOBJECTREFREPORTREQUEST(Base):
    __tablename__ = 'ARFOBJECTREFREPORTREQUEST'
    __bind_key__  = 'XORCISM'

    ARFObjectRefID = Column(Integer, primary_key=True)
    ReportRequestID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFOBJECTREFREPORTREQUEST {self.ARFObjectRefID}>'

class ARFRELATIONSHIP(Base):
    __tablename__ = 'ARFRELATIONSHIP'
    __bind_key__  = 'XORCISM'

    ARFRelationshipID = Column(Integer, primary_key=True)
    RelationshipTypeQName = Column(Text, nullable=False)
    RelationshipTypeID = Column(Integer)
    RelationshipScope = Column(Text)
    RelationshipSubjectNCName = Column(Text, nullable=False)

    def __repr__(self):
        return f'<ARFRELATIONSHIP {self.ARFRelationshipID}>'

class ARFRELATIONSHIPARFASSET(Base):
    __tablename__ = 'ARFRELATIONSHIPARFASSET'
    __bind_key__  = 'XORCISM'

    ARFRelationshipID = Column(Integer, primary_key=True)
    ARFAssetID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFRELATIONSHIPARFASSET {self.ARFRelationshipID}>'

class ARFRELATIONSHIPFORARFRELATIONSHIPS(Base):
    __tablename__ = 'ARFRELATIONSHIPFORARFRELATIONSHIPS'
    __bind_key__  = 'XORCISM'

    ARFRelationshipsID = Column(Integer, primary_key=True)
    ARFRelationshipID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFRELATIONSHIPFORARFRELATIONSHIPS {self.ARFRelationshipsID}>'

class ARFRELATIONSHIPREPORT(Base):
    __tablename__ = 'ARFRELATIONSHIPREPORT'
    __bind_key__  = 'XORCISM'

    ARFRelationshipID = Column(Integer, primary_key=True)
    ReportID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFRELATIONSHIPREPORT {self.ARFRelationshipID}>'

class ARFRELATIONSHIPREPORTREQUEST(Base):
    __tablename__ = 'ARFRELATIONSHIPREPORTREQUEST'
    __bind_key__  = 'XORCISM'

    ARFRelationshipID = Column(Integer, primary_key=True)
    ReportRequestID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ARFRELATIONSHIPREPORTREQUEST {self.ARFRelationshipID}>'

class ARFRELATIONSHIPS(Base):
    __tablename__ = 'ARFRELATIONSHIPS'
    __bind_key__  = 'XORCISM'

    ARFRelationshipsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ARFRELATIONSHIPS {self.ARFRelationshipsID}>'

class ARITHMETICFUNCTION(Base):
    __tablename__ = 'ARITHMETICFUNCTION'
    __bind_key__  = 'XORCISM'

    ArithmeticFunctionID = Column(Integer, primary_key=True)
    ArithmeticOperationName = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ARITHMETICFUNCTION {self.ArithmeticFunctionID}>'

class ARITHMETICOPERATION(Base):
    __tablename__ = 'ARITHMETICOPERATION'
    __bind_key__  = 'XORCISM'

    ArithmeticOperationID = Column(Integer, primary_key=True)
    ArithmeticOperationName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ARITHMETICOPERATION {self.ArithmeticOperationID}>'

class ARPCACHE(Base):
    __tablename__ = 'ARPCACHE'
    __bind_key__  = 'XORCISM'

    ARPCacheID = Column(Integer, primary_key=True)
    ARPCacheGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ARPCACHE {self.ARPCacheID}>'

class ARPCACHECHANGERECORD(Base):
    __tablename__ = 'ARPCACHECHANGERECORD'
    __bind_key__  = 'XORCISM'

    ARPCacheChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ARPCACHECHANGERECORD {self.ARPCacheChangeRecordID}>'

class ARPCACHEENTRIES(Base):
    __tablename__ = 'ARPCACHEENTRIES'
    __bind_key__  = 'XORCISM'

    ARPCacheEntriesID = Column(Integer, primary_key=True)
    ARPCacheID = Column(Integer, nullable=False)
    ARPCacheEntryID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)
    SuspectedMaliciousReasonGUID = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ARPCACHEENTRIES {self.ARPCacheEntriesID}>'

class ARPCACHEENTRY(Base):
    __tablename__ = 'ARPCACHEENTRY'
    __bind_key__  = 'XORCISM'

    ARPCacheEntryID = Column(Integer, primary_key=True)
    ARPCacheEntryGUID = Column(Text)
    IP_Address = Column(Integer)
    Physical_Address = Column(Text)
    ARPCacheEntryTypeID = Column(Integer)
    Network_Interface = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ARPCACHEENTRY {self.ARPCacheEntryID}>'

class ARPCACHEENTRYTYPE(Base):
    __tablename__ = 'ARPCACHEENTRYTYPE'
    __bind_key__  = 'XORCISM'

    ARPCacheEntryTypeID = Column(Integer, primary_key=True)
    ARPCacheEntryTypeName = Column(Text)
    ARPCacheEntryTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ARPCACHEENTRYTYPE {self.ARPCacheEntryTypeID}>'

class ARTIFACT(Base):
    __tablename__ = 'ARTIFACT'
    __bind_key__  = 'XORCISM'

    ArtifactID = Column(Integer, primary_key=True)
    ArtifactGUID = Column(Text)
    HashListID = Column(Integer)
    Raw_Artifact = Column(Text)
    RawArtifactID = Column(Integer)
    Raw_Artifact_Reference = Column(Text)
    ArtifactTypeID = Column(Integer, nullable=False)
    ArtifactTypeGUID = Column(Text)
    content_type = Column(Text)
    content_type_version = Column(Text)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)
    SuspectedMaliciousReasonGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    RepositoryID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ARTIFACT {self.ArtifactID}>'

class ARTIFACTCHANGERECORD(Base):
    __tablename__ = 'ARTIFACTCHANGERECORD'
    __bind_key__  = 'XORCISM'

    ArtifactChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ARTIFACTCHANGERECORD {self.ArtifactChangeRecordID}>'

class ARTIFACTHASHVALUE(Base):
    __tablename__ = 'ARTIFACTHASHVALUE'
    __bind_key__  = 'XORCISM'

    ArtifactHashValueID = Column(Integer, primary_key=True)
    ArtifactID = Column(Integer, nullable=False)
    ArtifactGUID = Column(Text)
    HashValueID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ARTIFACTHASHVALUE {self.ArtifactHashValueID}>'

class ARTIFACTPACKAGING(Base):
    __tablename__ = 'ARTIFACTPACKAGING'
    __bind_key__  = 'XORCISM'

    ArtifactPackagingID = Column(Integer, primary_key=True)
    ArtifactPackagingGUID = Column(Text)
    ArtifactID = Column(Integer, nullable=False)
    ArtifactGUID = Column(Text)
    PackagingID = Column(Integer, nullable=False)
    PackagingGUID = Column(Text)
    is_encrypted = Column(Integer)
    is_compressed = Column(Integer)
    ArtifactPackagingDescription = Column(Text)
    CollectedDate = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    RepositoryID = Column(Integer)
    RepositoryGUID = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ARTIFACTPACKAGING {self.ArtifactPackagingID}>'

class ARTIFACTTYPE(Base):
    __tablename__ = 'ARTIFACTTYPE'
    __bind_key__  = 'XORCISM'

    ArtifactTypeID = Column(Integer, primary_key=True)
    ArtifactTypeGUID = Column(Text)
    ArtifactTypeName = Column(Text)
    ArtifactTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    ImportanceID = Column(Integer)

    def __repr__(self):
        return f'<ARTIFACTTYPE {self.ArtifactTypeID}>'

class ASN(Base):
    __tablename__ = 'ASN'
    __bind_key__  = 'XORCISM'

    ASNID = Column(Integer, primary_key=True)
    AddressID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ASN {self.ASNID}>'

class ASOBJECT(Base):
    __tablename__ = 'ASOBJECT'
    __bind_key__  = 'XORCISM'

    ASObjectID = Column(Integer, primary_key=True)
    ASNumber = Column(Integer)
    ASName = Column(Text)
    ASHandle = Column(Text)
    Regional_Internet_Registry = Column(Text)
    OrganisationID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ASOBJECT {self.ASObjectID}>'

class ASSET(Base):
    __tablename__ = 'ASSET'
    __bind_key__  = 'XORCISM'

    AssetID = Column(Integer, primary_key=True)
    AssetGUID = Column(Text)
    AssetName = Column(Text)
    AssetDescription = Column(Text)
    AssetCriticalityLevel = Column(Text)
    TaskCriticalAsset = Column(Integer)
    DefenseCriticalAsset = Column(Integer)
    OSName = Column(Text)
    Enabled = Column(Integer)
    BLOB = Column(Text)
    LastCheckedDate = Column(Text)
    X500name = Column(Text)
    fqdn = Column(Text)
    hostname = Column(Text)
    motherboardguid = Column(Text)
    instancename = Column(Text)
    networkname = Column(Text)
    ipnetrangestartIPv4 = Column(Text)
    ipnetrangeendIPv4 = Column(Text)
    ipnetrangestartIPv6 = Column(Text)
    ipnetrangeendIPv6 = Column(Text)
    cidr = Column(Text)
    websiteurl = Column(Text)
    documentroot = Column(Text)
    locale = Column(Text)
    installationid = Column(Text)
    license = Column(Text)
    systemname = Column(Text)
    version = Column(Text)
    ipaddressIPv4 = Column(Text)
    ipaddressIPv6 = Column(Text)
    subnetmaskIPv4 = Column(Text)
    subnetmaskIPv6 = Column(Text)
    defaultrouteIPv4 = Column(Text)
    defaultrouteIPv6 = Column(Text)
    personal = Column(Integer)
    managedbythirdparty = Column(Integer)
    hostedbythirdparty = Column(Integer)
    notes = Column(Text)
    cloud = Column(Text)
    AssetImage = Column(Text)  # link / path of the asset's image
    PublicFacing = Column(Integer)  # asset publicly exposed / on the Internet (0/1)
    PersonID = Column(Integer)  # associated person (PERSON reference)
    PlatformID = Column(Integer)  # platform (input/selection PLATFORM.PlatformName)
    RiskScore = Column(Integer)  # computed risk score (recomputed every 30 s; see riskscore.ts)
    AssetLocation = Column(Text)  # free-text location of the asset (text)
    FinancialValue = Column(Float)  # financial value of the asset (monetary)
    AssetManagementID = Column(Integer)
    AssetOwnershipID = Column(Integer)
    AssetLocationID = Column(Integer)
    virtual = Column(Integer)
    ADParticipation = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<ASSET {self.AssetID}>'

class ASSETADDRESS(Base):
    __tablename__ = 'ASSETADDRESS'
    __bind_key__  = 'XORCISM'

    AssetAddressID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    AddressID = Column(Integer, nullable=False)
    AddressGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETADDRESS {self.AssetAddressID}>'

class ASSETARPCACHE(Base):
    __tablename__ = 'ASSETARPCACHE'
    __bind_key__  = 'XORCISM'

    AssetARPCacheID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    ARPCacheID = Column(Integer)
    ARPCacheGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETARPCACHE {self.AssetARPCacheID}>'

class ASSETAUDIT(Base):
    __tablename__ = 'ASSETAUDIT'
    __bind_key__  = 'XORCISM'

    AssetAuditID = Column(Integer, primary_key=True)
    AssetAuditGUID = Column(Text)
    AssetID = Column(Integer)
    AuditID = Column(Integer)  # AUDIT reference (XCOMPLIANCE database)
    Date = Column(Text)        # date (ISO 8601, like the other dates)
    ValidFrom = Column(Text)   # date (ISO 8601)
    ValidUntil = Column(Text)  # date (ISO 8601)
    ConfidenceLevel = Column(Integer)

    def __repr__(self):
        return f'<ASSETAUDIT {self.AssetAuditID}>'

class ASSETAUDITFINDING(Base):
    __tablename__ = 'ASSETAUDITFINDING'
    __bind_key__  = 'XORCISM'

    AssetAuditFindingID = Column(Integer, primary_key=True)
    AssetAuditFindingGUID = Column(Text)
    AssetID = Column(Integer)
    AuditFindingID = Column(Integer)  # AUDITFINDING reference (XCOMPLIANCE database)
    Date = Column(Text)               # date (ISO 8601, like the other dates)
    Status = Column(Text)
    ConfidenceLevel = Column(Integer)
    Criticity = Column(Integer)
    ValidFrom = Column(Text)   # date (ISO 8601) — validity window of the finding
    ValidUntil = Column(Text)  # date (ISO 8601) — used by the RiskScore computation

    def __repr__(self):
        return f'<ASSETAUDITFINDING {self.AssetAuditFindingID}>'

class ASSETBLACKLIST(Base):
    __tablename__ = 'ASSETBLACKLIST'
    __bind_key__  = 'XORCISM'

    AssetBlacklistID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    OrganisationID = Column(Integer)
    OrganisationGUID = Column(Text)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETBLACKLIST {self.AssetBlacklistID}>'

class ASSETCERTIFICATE(Base):
    __tablename__ = 'ASSETCERTIFICATE'
    __bind_key__  = 'XORCISM'

    AssetCertificateID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    CertificateID = Column(Integer, nullable=False)
    CertificateGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    AssetCertificateDescription = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETCERTIFICATE {self.AssetCertificateID}>'

class ASSETCERTIFICATEORGANISATION(Base):
    __tablename__ = 'ASSETCERTIFICATEORGANISATION'
    __bind_key__  = 'XORCISM'

    AssetCertificateOrganisationID = Column(Integer, primary_key=True)
    AssetCertificateID = Column(Integer, nullable=False)
    AssetCertificateGUID = Column(Text)
    OrganisationID = Column(Integer, nullable=False)
    OrganisationGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    AssetCertificateOrganisationDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETCERTIFICATEORGANISATION {self.AssetCertificateOrganisationID}>'

class ASSETCHANGERECORD(Base):
    __tablename__ = 'ASSETCHANGERECORD'
    __bind_key__  = 'XORCISM'

    AssetChangeRecordID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    ChangeRecordID = Column(Integer, nullable=False)
    ChangeRecordGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETCHANGERECORD {self.AssetChangeRecordID}>'

class ASSETCREDENTIAL(Base):
    __tablename__ = 'ASSETCREDENTIAL'
    __bind_key__  = 'XORCISM'

    AssetCredentialID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    AuthenticationTypeID = Column(Integer)
    AuthenticationTypeGUID = Column(Text)
    AuthenticationType = Column(Text)
    Username = Column(Text)
    Password = Column(Text)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    OrganisationID = Column(Integer)
    OrganisationGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETCREDENTIAL {self.AssetCredentialID}>'

class ASSETCRITICALITYLEVEL(Base):
    __tablename__ = 'ASSETCRITICALITYLEVEL'
    __bind_key__  = 'XORCISM'

    AssetCriticalityLevelID = Column(Integer, primary_key=True)
    AssetCriticalityLevelGUID = Column(Text)
    CriticalityLevelID = Column(Integer)
    AssetCriticalityLevelName = Column(Text)
    AssetCriticalityLevelDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETCRITICALITYLEVEL {self.AssetCriticalityLevelID}>'

class ASSETCRITICALITYLEVELFORASSET(Base):
    __tablename__ = 'ASSETCRITICALITYLEVELFORASSET'
    __bind_key__  = 'XORCISM'

    AssetCriticalityID = Column(Integer, primary_key=True)
    AssetCriticalityDescription = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetCriticalityLevelID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETCRITICALITYLEVELFORASSET {self.AssetCriticalityID}>'

class ASSETDEVICE(Base):
    __tablename__ = 'ASSETDEVICE'
    __bind_key__  = 'XORCISM'

    AssetDeviceID = Column(Integer, primary_key=True)
    AssetDeviceGUID = Column(Text)
    AssetDeviceDescription = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    DeviceID = Column(Integer, nullable=False)
    DeviceGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETDEVICE {self.AssetDeviceID}>'

class ASSETFORASSET(Base):
    __tablename__ = 'ASSETFORASSET'
    __bind_key__  = 'XORCISM'

    AssetForAssetID = Column(Integer, primary_key=True)
    AssetRefID = Column(Integer, nullable=False)
    AssetRefGUID = Column(Text)
    AssetRelationshipID = Column(Integer)
    relationshiptype = Column(Text)
    relationshipscope = Column(Text)
    AssetSubjectID = Column(Integer, nullable=False)
    AssetSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETFORASSET {self.AssetForAssetID}>'

class ASSETFORORGANISATION(Base):
    __tablename__ = 'ASSETFORORGANISATION'
    __bind_key__  = 'XORCISM'

    AssetForOrganisationID = Column(Integer, primary_key=True)
    OrganisationAssetGUID = Column(Text)
    OrganisationID = Column(Integer, nullable=False)
    OrganisationGUID = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETFORORGANISATION {self.AssetForOrganisationID}>'

class ASSETFORTHREATACTORTTP(Base):
    __tablename__ = 'ASSETFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    AssetForThreatActorTTPID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    ThreatActorTTPID = Column(Integer, nullable=False)
    ThreatActorTTPGUID = Column(Text)
    Information_Source = Column(Text)
    ConfidenceLevel = Column(Text)
    ConfidenceLevelID = Column(Integer)
    notes = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETFORTHREATACTORTTP {self.AssetForThreatActorTTPID}>'

class ASSETFUNCTION(Base):
    __tablename__ = 'ASSETFUNCTION'
    __bind_key__  = 'XORCISM'

    AssetFunctionID = Column(Integer, primary_key=True)
    AssetFunctionName = Column(Text, nullable=False)
    AssetFunctionDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETFUNCTION {self.AssetFunctionID}>'

class ASSETFUNCTIONFORASSET(Base):
    __tablename__ = 'ASSETFUNCTIONFORASSET'
    __bind_key__  = 'XORCISM'

    AssetAssetFunctionID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetFunctionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETFUNCTIONFORASSET {self.AssetAssetFunctionID}>'

class ASSETGEOLOCATION(Base):
    __tablename__ = 'ASSETGEOLOCATION'
    __bind_key__  = 'XORCISM'

    AssetGeoLocationID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    GeoLocationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    CollectionTimestamp = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETGEOLOCATION {self.AssetGeoLocationID}>'

class ASSETGROUP(Base):
    __tablename__ = 'ASSETGROUP'
    __bind_key__  = 'XORCISM'

    AssetGroupID = Column(Integer, primary_key=True)
    AssetGroupGUID = Column(Text)
    AssetForAssetID = Column(Integer)
    AssetGroupName = Column(Text)
    AssetGroupDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    OrganisationID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETGROUP {self.AssetGroupID}>'

class ASSETINFORMATION(Base):
    __tablename__ = 'ASSETINFORMATION'
    __bind_key__  = 'XORCISM'

    AssetInformationID = Column(Integer, primary_key=True)
    hostname = Column(Text)
    netbios = Column(Text)
    hosttype = Column(Text)
    JobID = Column(Integer, nullable=False)
    information = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ASSETINFORMATION {self.AssetInformationID}>'

class ASSETLICENSE(Base):
    __tablename__ = 'ASSETLICENSE'
    __bind_key__  = 'XORCISM'

    AssetLicenseID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    LicenseNumber = Column(Text)
    LicenseValue = Column(Text)
    LicenseID = Column(Integer)
    LicenseFileID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETLICENSE {self.AssetLicenseID}>'

class ASSETLOCATION(Base):
    __tablename__ = 'ASSETLOCATION'
    __bind_key__  = 'XORCISM'

    AssetLocationID = Column(Integer, primary_key=True)
    AssetLocationType = Column(Text, nullable=False)
    AssetLocationDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ASSETLOCATION {self.AssetLocationID}>'

class ASSETLOCATIONFORASSET(Base):
    __tablename__ = 'ASSETLOCATIONFORASSET'
    __bind_key__  = 'XORCISM'

    AssetLocationTimeID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetLocationID = Column(Integer, nullable=False)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CreatedDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETLOCATIONFORASSET {self.AssetLocationTimeID}>'

class ASSETMANAGEMENT(Base):
    __tablename__ = 'ASSETMANAGEMENT'
    __bind_key__  = 'XORCISM'

    AssetManagementID = Column(Integer, primary_key=True)
    ManagementID = Column(Integer)
    ManagementType = Column(Text, nullable=False)
    ManagementDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETMANAGEMENT {self.AssetManagementID}>'

class ASSETMANAGEMENTFORASSET(Base):
    __tablename__ = 'ASSETMANAGEMENTFORASSET'
    __bind_key__  = 'XORCISM'

    AssetManagementTimeID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetManagementID = Column(Integer, nullable=False)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETMANAGEMENTFORASSET {self.AssetManagementTimeID}>'

class ASSETMEMORYDUMP(Base):
    __tablename__ = 'ASSETMEMORYDUMP'
    __bind_key__  = 'XORCISM'

    AssetMemoryDumpID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ASSETMEMORYDUMP {self.AssetMemoryDumpID}>'

class ASSETNETWORKZONE(Base):
    __tablename__ = 'ASSETNETWORKZONE'
    __bind_key__  = 'XORCISM'

    AssetNetworkZoneID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    NetworkZoneID = Column(Integer)
    NetworkZoneGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    LastCheckedDate = Column(Text)
    ConfidentialityLevelID = Column(Integer)

    def __repr__(self):
        return f'<ASSETNETWORKZONE {self.AssetNetworkZoneID}>'

class ASSETNETWORKZONERESTRICTION(Base):
    __tablename__ = 'ASSETNETWORKZONERESTRICTION'
    __bind_key__  = 'XORCISM'

    AssetNetworkZoneRestrictionID = Column(Integer, primary_key=True)
    AssetNetworkZoneRestrictionDescription = Column(Text)
    AssetNetworkZoneID = Column(Integer, nullable=False)
    AssetNetworkZoneGUID = Column(Text)
    RestrictionID = Column(Integer, nullable=False)
    CreationDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<ASSETNETWORKZONERESTRICTION {self.AssetNetworkZoneRestrictionID}>'

class ASSETORGANIZATIONALUNIT(Base):
    __tablename__ = 'ASSETORGANIZATIONALUNIT'
    __bind_key__  = 'XORCISM'

    AssetOrganizationalUnitID = Column(Integer, primary_key=True)
    OrganizationalUnitID = Column(Integer, nullable=False)
    AssetID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETORGANIZATIONALUNIT {self.AssetOrganizationalUnitID}>'

class ASSETOWNERSHIP(Base):
    __tablename__ = 'ASSETOWNERSHIP'
    __bind_key__  = 'XORCISM'

    AssetOwnershipID = Column(Integer, primary_key=True)
    OwnershipID = Column(Integer)
    OwnershipName = Column(Text, nullable=False)
    OwnershipDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ASSETOWNERSHIP {self.AssetOwnershipID}>'

class ASSETPERIMETER(Base):
    __tablename__ = 'ASSETPERIMETER'
    __bind_key__  = 'XORCISM'

    AssetPerimeterID = Column(Integer, primary_key=True)
    AssetPerimeterGUID = Column(Text)

    def __repr__(self):
        return f'<ASSETPERIMETER {self.AssetPerimeterID}>'

class ASSETPERIMETERASSET(Base):
    __tablename__ = 'ASSETPERIMETERASSET'
    __bind_key__  = 'XORCISM'

    AssetPerimeterAssetID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ASSETPERIMETERASSET {self.AssetPerimeterAssetID}>'

class ASSETPERIMETERNETWORKZONE(Base):
    __tablename__ = 'ASSETPERIMETERNETWORKZONE'
    __bind_key__  = 'XORCISM'

    AssetPerimeterNetworkZoneID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ASSETPERIMETERNETWORKZONE {self.AssetPerimeterNetworkZoneID}>'

class ASSETPERIMETERSECURITYCONTROL(Base):
    __tablename__ = 'ASSETPERIMETERSECURITYCONTROL'
    __bind_key__  = 'XORCISM'

    AssetPerimeterSecurityControlID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ASSETPERIMETERSECURITYCONTROL {self.AssetPerimeterSecurityControlID}>'

class ASSETPHYSICALLOCATION(Base):
    __tablename__ = 'ASSETPHYSICALLOCATION'
    __bind_key__  = 'XORCISM'

    AssetPhysicalLocationTimeID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    PhysicalLocationID = Column(Integer, nullable=False)
    BLOB = Column(Text)
    InformationPersonID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETPHYSICALLOCATION {self.AssetPhysicalLocationTimeID}>'

class ASSETPLATFORM(Base):
    __tablename__ = 'ASSETPLATFORM'
    __bind_key__  = 'XORCISM'

    AssetPlatformID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    PlatformID = Column(Integer)
    PlatformGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    LastCheckedDate = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETPLATFORM {self.AssetPlatformID}>'


class ASSETOVALDEFINITION(Base):
    __tablename__ = 'ASSETOVALDEFINITION'
    __bind_key__  = 'XORCISM'

    AssetOVALDefinitionID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)            # ASSET reference
    OVALDefinitionID = Column(Integer)   # OVALDEFINITION reference (XOVAL database)
    Status = Column(Text)
    ConfidenceLevel = Column(Text)
    CreatedDate = Column(Text)           # date
    ValidFrom = Column(Text)             # date
    ValidUntil = Column(Text)            # date

    def __repr__(self):
        return f'<ASSETOVALDEFINITION {self.AssetOVALDefinitionID}>'

class ASSETFINANCIALVALUE(Base):
    __tablename__ = 'ASSETFINANCIALVALUE'
    __bind_key__  = 'XORCISM'

    AssetFinancialValueID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)            # ASSET reference
    FinancialValue = Column(Integer)     # financial value (monetary)
    Currency = Column(Text)              # devise (USD, EUR…)
    CreatedDate = Column(Text)           # date
    ValidFrom = Column(Text)             # date
    ValidUntil = Column(Text)            # date
    PersonID = Column(Integer)           # PERSON reference (author of the valuation)

    def __repr__(self):
        return f'<ASSETFINANCIALVALUE {self.AssetFinancialValueID}>'

class ASSETPRODUCT(Base):
    __tablename__ = 'ASSETPRODUCT'
    __bind_key__  = 'XORCISM'

    AssetProductID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    ProductID = Column(Integer, nullable=False)
    ProductGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    LastCheckedDate = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETPRODUCT {self.AssetProductID}>'

class ASSETRELATIONSHIP(Base):
    __tablename__ = 'ASSETRELATIONSHIP'
    __bind_key__  = 'XORCISM'

    AssetRelationshipID = Column(Integer, primary_key=True)
    relationshiptype = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETRELATIONSHIP {self.AssetRelationshipID}>'

class ASSETREPORTCOLLECTION(Base):
    __tablename__ = 'ASSETREPORTCOLLECTION'
    __bind_key__  = 'XORCISM'

    AssetReportCollectionID = Column(Integer, primary_key=True)
    ARFReportCollectionID = Column(Text)
    ReportRequestsID = Column(Integer)
    AssetsID = Column(Integer)
    ReportsID = Column(Integer)
    ARFRelationshipsID = Column(Integer)
    ARFExtendedInfosID = Column(Integer)

    def __repr__(self):
        return f'<ASSETREPORTCOLLECTION {self.AssetReportCollectionID}>'

class ASSETRISKRATING(Base):
    __tablename__ = 'ASSETRISKRATING'
    __bind_key__  = 'XORCISM'

    AssetRiskRatingID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    RiskRatingID = Column(Integer, nullable=False)
    AssetRiskRatingDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETRISKRATING {self.AssetRiskRatingID}>'

class ASSETRISKSCORE(Base):
    __tablename__ = 'ASSETRISKSCORE'
    __bind_key__  = 'XORCISM'

    AssetRiskScoreID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    Date = Column(Text)  # score date (ISO 8601, like the other dates)
    RiskScore = Column(Integer)
    ConfidenceLevel = Column(Integer)
    TrustLevel = Column(Integer)

    def __repr__(self):
        return f'<ASSETRISKSCORE {self.AssetRiskScoreID}>'

class ASSETROLE(Base):
    __tablename__ = 'ASSETROLE'
    __bind_key__  = 'XORCISM'

    AssetRoleID = Column(Integer, primary_key=True)
    AssetRoleGUID = Column(Text)
    AssetRoleName = Column(Text, nullable=False)
    AssetRoleDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETROLE {self.AssetRoleID}>'

class ASSETROLEFORASSET(Base):
    __tablename__ = 'ASSETROLEFORASSET'
    __bind_key__  = 'XORCISM'

    AssetRoleForAssetID = Column(Integer, primary_key=True)
    AssetAssetRoleGUID = Column(Text)
    AssetRoleID = Column(Integer, nullable=False)
    AssetRoleGUID = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETROLEFORASSET {self.AssetRoleForAssetID}>'

class ASSETS(Base):
    __tablename__ = 'ASSETS'
    __bind_key__  = 'XORCISM'

    AssetsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ASSETS {self.AssetsID}>'

class ASSETSECURITYCONTROL(Base):
    __tablename__ = 'ASSETSECURITYCONTROL'
    __bind_key__  = 'XORCISM'

    AssetSecurityControlID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    SecurityControlID = Column(Integer, nullable=False)
    SecurityControlGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    LastCheckedDate = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ImportanceID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<ASSETSECURITYCONTROL {self.AssetSecurityControlID}>'

class ASSETSENSOR(Base):
    __tablename__ = 'ASSETSENSOR'
    __bind_key__  = 'XORCISM'

    AssetSensorID = Column(Integer, primary_key=True)
    AssetSensorGUID = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    SensorID = Column(Integer, nullable=False)
    SensorGUID = Column(Text)
    AssetSensorName = Column(Text)
    AssetSensorDescription = Column(Text)
    CreatedDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETSENSOR {self.AssetSensorID}>'

class ASSETSESSION(Base):
    __tablename__ = 'ASSETSESSION'
    __bind_key__  = 'XORCISM'

    AssetSessionID = Column(Integer, primary_key=True)
    AssetSessionGUID = Column(Text)
    SessionID = Column(Integer)
    SessionGUID = Column(Text)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ASSETSESSION {self.AssetSessionID}>'

class ASSETSYNTHETICID(Base):
    __tablename__ = 'ASSETSYNTHETICID'
    __bind_key__  = 'XORCISM'

    AssetSyntheticID = Column(Integer, primary_key=True)
    AssetSyntheticIDGUID = Column(Text)
    resource = Column(Text, nullable=False)
    id = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ASSETSYNTHETICID {self.AssetSyntheticID}>'

class ASSETSYNTHETICIDFORASSET(Base):
    __tablename__ = 'ASSETSYNTHETICIDFORASSET'
    __bind_key__  = 'XORCISM'

    AssetAssetSyntheticID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    AssetSyntheticID = Column(Integer, nullable=False)
    AssetSyntheticIDGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ASSETSYNTHETICIDFORASSET {self.AssetAssetSyntheticID}>'

class ASSETTECHNOLOGY(Base):
    __tablename__ = 'ASSETTECHNOLOGY'
    __bind_key__  = 'XORCISM'

    AssetTechnologyID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    TechnologyID = Column(Integer)
    TechnologyGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETTECHNOLOGY {self.AssetTechnologyID}>'

class ASSETTHREAT(Base):
    __tablename__ = 'ASSETTHREAT'
    __bind_key__  = 'XORCISM'

    AssetThreatID = Column(Integer, primary_key=True)
    AssetThreatGUID = Column(Text)
    AssetID = Column(Integer)
    ThreatID = Column(Integer)
    ValidFrom = Column(Text)   # date (ISO 8601, like the other dates)
    ValidUntil = Column(Text)  # date (ISO 8601)
    ConfidenceLevel = Column(Integer)
    TrustLevel = Column(Integer)
    Criticity = Column(Integer)

    def __repr__(self):
        return f'<ASSETTHREAT {self.AssetThreatID}>'

class ASSETVALUE(Base):
    __tablename__ = 'ASSETVALUE'
    __bind_key__  = 'XORCISM'

    AssetValueID = Column(Integer, primary_key=True)
    AssetValueName = Column(Text, nullable=False)
    AssetValueDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ASSETVALUE {self.AssetValueID}>'

class ASSETVALUEFORASSET(Base):
    __tablename__ = 'ASSETVALUEFORASSET'
    __bind_key__  = 'XORCISM'

    AssetValueForAssetID = Column(Integer, primary_key=True)
    AssetAssetValueGUID = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    AssetValueID = Column(Integer, nullable=False)
    AssetValueGUID = Column(Text)
    ValueValue = Column(Text)
    iso_currency_code = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETVALUEFORASSET {self.AssetValueForAssetID}>'

class ASSETVARIETY(Base):
    __tablename__ = 'ASSETVARIETY'
    __bind_key__  = 'XORCISM'

    AssetVarietyID = Column(Integer, primary_key=True)
    AssetVarietyName = Column(Text, nullable=False)
    AssetVarietyDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ASSETVARIETY {self.AssetVarietyID}>'

class ASSETVARIETYFORASSET(Base):
    __tablename__ = 'ASSETVARIETYFORASSET'
    __bind_key__  = 'XORCISM'

    AssetAssetVarietyID = Column(Integer, primary_key=True)
    AssetVarietyID = Column(Integer, nullable=False)
    AssetVarietyGUID = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETVARIETYFORASSET {self.AssetAssetVarietyID}>'

class ASSETVULNERABILITY(Base):
    __tablename__ = 'ASSETVULNERABILITY'
    __bind_key__  = 'XORCISM'

    AssetVulnerabilityID = Column(Integer, nullable=False, primary_key=True)
    AssetID = Column(Integer)
    VulnerabilityID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ToolID = Column(Integer)
    AssetVulnerabilityStatusID = Column(Integer)
    Status = Column(Integer)
    TotalControl = Column(Integer)  # 0/1 (checkbox in the form)

    def __repr__(self):
        return f'<ASSETVULNERABILITY {self.AssetVulnerabilityID}>'

class ASSETWHITELIST(Base):
    __tablename__ = 'ASSETWHITELIST'
    __bind_key__  = 'XORCISM'

    AssetWhitelistID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ASSETWHITELIST {self.AssetWhitelistID}>'

class ASSETZONE(Base):
    __tablename__ = 'ASSETZONE'
    __bind_key__  = 'XORCISM'

    AssetZoneID = Column(Integer, primary_key=True)
    AssetZoneGUID = Column(Text)
    AssetID = Column(Integer)
    ZoneID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ASSETZONE {self.AssetZoneID}>'

class ASSOCIATION(Base):
    __tablename__ = 'ASSOCIATION'
    __bind_key__  = 'XORCISM'

    AssociationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ASSOCIATION {self.AssociationID}>'

class ASSOCIATIONRULE(Base):
    __tablename__ = 'ASSOCIATIONRULE'
    __bind_key__  = 'XORCISM'

    AssociationRuleID = Column(Integer, primary_key=True)
    RuleID = Column(Integer)

    def __repr__(self):
        return f'<ASSOCIATIONRULE {self.AssociationRuleID}>'

class ASSURANCE(Base):
    __tablename__ = 'ASSURANCE'
    __bind_key__  = 'XORCISM'

    AssuranceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ASSURANCE {self.AssuranceID}>'

class ASSURANCEREQUIREMENT(Base):
    __tablename__ = 'ASSURANCEREQUIREMENT'
    __bind_key__  = 'XORCISM'

    AssuranceRequirementID = Column(Integer, primary_key=True)
    RequirementID = Column(Integer)
    RequirementGUID = Column(Text)
    AssuranceRequirementGUID = Column(Text)
    AssuranceRequirementTitle = Column(Text)
    AssuranceRequirementDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ASSURANCEREQUIREMENT {self.AssuranceRequirementID}>'

class ATTACHMENT(Base):
    __tablename__ = 'ATTACHMENT'
    __bind_key__  = 'XORCISM'

    AttachmentID = Column(Integer, primary_key=True)
    AttachmentGUID = Column(Text)
    FileID = Column(Integer)
    FileGUID = Column(Text)
    MIMEID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACHMENT {self.AttachmentID}>'

class ATTACHMENTREFERENCE(Base):
    __tablename__ = 'ATTACHMENTREFERENCE'
    __bind_key__  = 'XORCISM'

    AttachmentReferenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ATTACHMENTREFERENCE {self.AttachmentReferenceID}>'

class ATTRIBUTE(Base):
    __tablename__ = 'ATTRIBUTE'
    __bind_key__  = 'XORCISM'

    AttributeID = Column(Integer, primary_key=True)
    AttributeName = Column(Text)
    AttributeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTRIBUTE {self.AttributeID}>'

class ATTRIBUTEVALUE(Base):
    __tablename__ = 'ATTRIBUTEVALUE'
    __bind_key__  = 'XORCISM'

    AttributeValueID = Column(Integer, primary_key=True)
    AttributeID = Column(Integer, nullable=False)
    AttributeValueName = Column(Text)
    AttributeValueDescription = Column(Text)
    AttributeValueType = Column(Text)
    AttributeValue = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTRIBUTEVALUE {self.AttributeValueID}>'

class AUDIT(Base):
    __tablename__ = 'AUDIT'
    __bind_key__  = 'XORCISM'

    AuditID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer)

    def __repr__(self):
        return f'<AUDIT {self.AuditID}>'

class AUDITFINDING(Base):
    __tablename__ = 'AUDITFINDING'
    __bind_key__  = 'XORCISM'

    AuditFindingID = Column(Integer, primary_key=True)
    AuditID = Column(Integer, nullable=False)
    FindingID = Column(Integer, nullable=False)
    AuditProcedureID = Column(Integer)
    AuditFindingName = Column(Text)
    AuditFindingDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<AUDITFINDING {self.AuditFindingID}>'

class AUDITLOGEVENT(Base):
    __tablename__ = 'AUDITLOGEVENT'
    __bind_key__  = 'XORCISM'

    AuditLogEventID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<AUDITLOGEVENT {self.AuditLogEventID}>'

class AUDITPROCEDURE(Base):
    __tablename__ = 'AUDITPROCEDURE'
    __bind_key__  = 'XORCISM'

    AuditProcedureID = Column(Integer, primary_key=True)
    AuditProcedureName = Column(Text)
    AuditProcedureDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<AUDITPROCEDURE {self.AuditProcedureID}>'

class AUTHENTICATIONTOKENPROTECTIONMECHANISM(Base):
    __tablename__ = 'AUTHENTICATIONTOKENPROTECTIONMECHANISM'
    __bind_key__  = 'XORCISM'

    AuthenticationTokenProtectionMechanismID = Column(Integer, primary_key=True)
    AuthenticationTokenProtectionMechanismGUID = Column(Text)
    AuthenticationTokenProtectionMechanismName = Column(Text)
    AuthenticationTokenProtectionMechanismDescription = Column(Text)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<AUTHENTICATIONTOKENPROTECTIONMECHANISM {self.AuthenticationTokenProtectionMechanismID}>'

class AUTHENTICATIONTOKENPROTECTIONMECHANISMBLACKLIST(Base):
    __tablename__ = 'AUTHENTICATIONTOKENPROTECTIONMECHANISMBLACKLIST'
    __bind_key__  = 'XORCISM'

    AuthenticationTokenProtectionMechanismBlacklistID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<AUTHENTICATIONTOKENPROTECTIONMECHANISMBLACKLIST {self.AuthenticationTokenProtectionMechanismBlacklistID}>'

class AUTHENTICATIONTYPE(Base):
    __tablename__ = 'AUTHENTICATIONTYPE'
    __bind_key__  = 'XORCISM'

    AuthenticationTypeID = Column(Integer, primary_key=True)
    AuthenticationTypeGUID = Column(Text)
    AuthenticationTypeName = Column(Text)
    AuthenticationTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<AUTHENTICATIONTYPE {self.AuthenticationTypeID}>'

class AUTHENTICATIONTYPEBLACKLIST(Base):
    __tablename__ = 'AUTHENTICATIONTYPEBLACKLIST'
    __bind_key__  = 'XORCISM'

    AuthenticationTypeBlacklistID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<AUTHENTICATIONTYPEBLACKLIST {self.AuthenticationTypeBlacklistID}>'

class AUTHENTICATIONTYPEDESCRIPTION(Base):
    __tablename__ = 'AUTHENTICATIONTYPEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    AuthenticationTypeDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<AUTHENTICATIONTYPEDESCRIPTION {self.AuthenticationTypeDescriptionID}>'

class AUTHENTICATIONTYPEREFERENCE(Base):
    __tablename__ = 'AUTHENTICATIONTYPEREFERENCE'
    __bind_key__  = 'XORCISM'

    AuthenticationTypeReferenceID = Column(Integer, primary_key=True)
    AuthenticationTypeID = Column(Integer)
    AuthenticationTypeGUID = Column(Text)
    ReferenceID = Column(Integer)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<AUTHENTICATIONTYPEREFERENCE {self.AuthenticationTypeReferenceID}>'

class AUTHOR(Base):
    __tablename__ = 'AUTHOR'
    __bind_key__  = 'XORCISM'

    AuthorID = Column(Integer, primary_key=True)
    AuthorName = Column(Text, nullable=False)
    PersonID = Column(Integer)
    OrganisationID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<AUTHOR {self.AuthorID}>'

class AVAILABILITYLOSSTYPE(Base):
    __tablename__ = 'AVAILABILITYLOSSTYPE'
    __bind_key__  = 'XORCISM'

    AvailabilityLossTypeID = Column(Integer, primary_key=True)
    AvailabilityLossTypeName = Column(Text)
    AvailabilityLossTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<AVAILABILITYLOSSTYPE {self.AvailabilityLossTypeID}>'

class AVAILABILITYVIOLATIONPROPERTIES(Base):
    __tablename__ = 'AVAILABILITYVIOLATIONPROPERTIES'
    __bind_key__  = 'XORCISM'

    AvailabilityViolationPropertiesID = Column(Integer, primary_key=True)
    AvailabilityViolationPropertiesName = Column(Text)
    AvailabilityViolationPropertiesDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ieEncrypted = Column(Integer)

    def __repr__(self):
        return f'<AVAILABILITYVIOLATIONPROPERTIES {self.AvailabilityViolationPropertiesID}>'

class AVAILABILITYVIOLATIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'AVAILABILITYVIOLATIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AvailabilityViolationStrategicObjectiveID = Column(Integer, primary_key=True)
    AvailabilityViolationStrategicObjectiveName = Column(Text)
    AvailabilityViolationStrategicObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<AVAILABILITYVIOLATIONSTRATEGICOBJECTIVE {self.AvailabilityViolationStrategicObjectiveID}>'

class AVAILABILITYVIOLATIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'AVAILABILITYVIOLATIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    AvailabilityViolationTacticalObjectiveID = Column(Integer, primary_key=True)
    AvailabilityViolationTacticalObjectiveName = Column(Text)
    AvailabilityViolationTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<AVAILABILITYVIOLATIONTACTICALOBJECTIVE {self.AvailabilityViolationTacticalObjectiveID}>'

class BANNER(Base):
    __tablename__ = 'BANNER'
    __bind_key__  = 'XORCISM'

    BannerID = Column(Integer, primary_key=True)
    BannerGUID = Column(Text)
    BannerName = Column(Text)
    BannerDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<BANNER {self.BannerID}>'

class BANNERREGEX(Base):
    __tablename__ = 'BANNERREGEX'
    __bind_key__  = 'XORCISM'

    BannerRegexID = Column(Integer, primary_key=True)
    BannerRegexGUID = Column(Text)
    BannerID = Column(Integer, nullable=False)
    BannerGUID = Column(Text)
    RegexID = Column(Integer, nullable=False)
    RegexGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<BANNERREGEX {self.BannerRegexID}>'

class BEGINFUNCTION(Base):
    __tablename__ = 'BEGINFUNCTION'
    __bind_key__  = 'XORCISM'

    BeginFunctionID = Column(Integer, primary_key=True)
    StartsWithCharacters = Column(Text, nullable=False)
    OVALComponentGroupID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<BEGINFUNCTION {self.BeginFunctionID}>'

class BEHAVIOMETRIC(Base):
    __tablename__ = 'BEHAVIOMETRIC'
    __bind_key__  = 'XORCISM'

    BehaviometricID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIOMETRIC {self.BehaviometricID}>'

class BEHAVIOR(Base):
    __tablename__ = 'BEHAVIOR'
    __bind_key__  = 'XORCISM'

    BehaviorID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIOR {self.BehaviorID}>'

class BEHAVIORACTIONCOMPOSITION(Base):
    __tablename__ = 'BEHAVIORACTIONCOMPOSITION'
    __bind_key__  = 'XORCISM'

    BehaviorActionCompositionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIORACTIONCOMPOSITION {self.BehaviorActionCompositionID}>'

class BEHAVIORALCHARACTERISTIC(Base):
    __tablename__ = 'BEHAVIORALCHARACTERISTIC'
    __bind_key__  = 'XORCISM'

    BehavioralCharacteristicID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIORALCHARACTERISTIC {self.BehavioralCharacteristicID}>'

class BEHAVIORASSOCIATEDCODE(Base):
    __tablename__ = 'BEHAVIORASSOCIATEDCODE'
    __bind_key__  = 'XORCISM'

    BehaviorAssociatedCodeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIORASSOCIATEDCODE {self.BehaviorAssociatedCodeID}>'

class BEHAVIORCOLLECTION(Base):
    __tablename__ = 'BEHAVIORCOLLECTION'
    __bind_key__  = 'XORCISM'

    BehaviorCollectionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIORCOLLECTION {self.BehaviorCollectionID}>'

class BEHAVIORDESCRIPTION(Base):
    __tablename__ = 'BEHAVIORDESCRIPTION'
    __bind_key__  = 'XORCISM'

    BehaviorDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIORDESCRIPTION {self.BehaviorDescriptionID}>'

class BEHAVIORDISCOVERYMETHOD(Base):
    __tablename__ = 'BEHAVIORDISCOVERYMETHOD'
    __bind_key__  = 'XORCISM'

    BehaviorDiscoveryMethodID = Column(Integer, primary_key=True)
    BehaviorID = Column(Integer)
    DiscoveryMethodID = Column(Integer)

    def __repr__(self):
        return f'<BEHAVIORDISCOVERYMETHOD {self.BehaviorDiscoveryMethodID}>'

class BEHAVIORIDMATCHINGPATTERN(Base):
    __tablename__ = 'BEHAVIORIDMATCHINGPATTERN'
    __bind_key__  = 'XORCISM'

    BehaviorIDPatternID = Column(Integer, primary_key=True)
    BehaviorIDPatternGUID = Column(Text)
    BehaviorID = Column(Integer, nullable=False)
    BehaviorGUID = Column(Text)
    BehaviorIDMatchingPattern = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<BEHAVIORIDMATCHINGPATTERN {self.BehaviorIDPatternID}>'

class BEHAVIORIDPATTERN(Base):
    __tablename__ = 'BEHAVIORIDPATTERN'
    __bind_key__  = 'XORCISM'

    BehaviorIDPatternID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIORIDPATTERN {self.BehaviorIDPatternID}>'

class BEHAVIORPURPOSE(Base):
    __tablename__ = 'BEHAVIORPURPOSE'
    __bind_key__  = 'XORCISM'

    BehaviorPurposeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIORPURPOSE {self.BehaviorPurposeID}>'

class BEHAVIORRELATIONSHIPS(Base):
    __tablename__ = 'BEHAVIORRELATIONSHIPS'
    __bind_key__  = 'XORCISM'

    BehaviorRelationShipsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BEHAVIORRELATIONSHIPS {self.BehaviorRelationShipsID}>'

class BIOMETRIC(Base):
    __tablename__ = 'BIOMETRIC'
    __bind_key__  = 'XORCISM'

    BiometricID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BIOMETRIC {self.BiometricID}>'

class BREACH(Base):
    __tablename__ = 'BREACH'
    __bind_key__  = 'XORCISM'

    BreachID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BREACH {self.BreachID}>'

class BREACHDESCRIPTION(Base):
    __tablename__ = 'BREACHDESCRIPTION'
    __bind_key__  = 'XORCISM'

    BreachDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BREACHDESCRIPTION {self.BreachDescriptionID}>'

class BREACHEVIDENCE(Base):
    __tablename__ = 'BREACHEVIDENCE'
    __bind_key__  = 'XORCISM'

    BreachEvidenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BREACHEVIDENCE {self.BreachEvidenceID}>'

class BREACHFINDING(Base):
    __tablename__ = 'BREACHFINDING'
    __bind_key__  = 'XORCISM'

    BreachFindingID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BREACHFINDING {self.BreachFindingID}>'

class BREACHNOTIFICATION(Base):
    __tablename__ = 'BREACHNOTIFICATION'
    __bind_key__  = 'XORCISM'

    BreachNotificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BREACHNOTIFICATION {self.BreachNotificationID}>'

class BREACHTAG(Base):
    __tablename__ = 'BREACHTAG'
    __bind_key__  = 'XORCISM'

    BreachTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BREACHTAG {self.BreachTagID}>'

class BREAK(Base):
    __tablename__ = 'BREAK'
    __bind_key__  = 'XORCISM'

    BreakID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BREAK {self.BreakID}>'

class BROWSER(Base):
    __tablename__ = 'BROWSER'
    __bind_key__  = 'XORCISM'

    BrowserID = Column(Integer, primary_key=True)
    SoftwareID = Column(Integer)

    def __repr__(self):
        return f'<BROWSER {self.BrowserID}>'

class BROWSERCHARACTERISTIC(Base):
    __tablename__ = 'BROWSERCHARACTERISTIC'
    __bind_key__  = 'XORCISM'

    BrowserCharacteristicID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BROWSERCHARACTERISTIC {self.BrowserCharacteristicID}>'

class BULLETIN(Base):
    __tablename__ = 'BULLETIN'
    __bind_key__  = 'XORCISM'

    BulletinID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BULLETIN {self.BulletinID}>'

class BUSINESSIMPACT(Base):
    __tablename__ = 'BUSINESSIMPACT'
    __bind_key__  = 'XORCISM'

    BusinessImpactID = Column(Integer, primary_key=True)
    BusinessImpactGUID = Column(Text)
    ImpactLevel = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<BUSINESSIMPACT {self.BusinessImpactID}>'

class BUSINESSIMPACTFORBUSINESSRISK(Base):
    __tablename__ = 'BUSINESSIMPACTFORBUSINESSRISK'
    __bind_key__  = 'XORCISM'

    BusinessRiskBusinessImpactID = Column(Integer, primary_key=True)
    BusinessImpactID = Column(Integer, nullable=False)
    BusinessImpactGUID = Column(Text)
    BusinessRiskID = Column(Integer, nullable=False)
    BusinessRiskGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<BUSINESSIMPACTFORBUSINESSRISK {self.BusinessRiskBusinessImpactID}>'

class BUSINESSIMPACTFORREGULATORYRISK(Base):
    __tablename__ = 'BUSINESSIMPACTFORREGULATORYRISK'
    __bind_key__  = 'XORCISM'

    RegulatoryRiskBusinessImpactID = Column(Integer, primary_key=True)
    BusinessImpactID = Column(Integer, nullable=False)
    BusinessImpactGUID = Column(Text)
    RegulatoryRiskID = Column(Integer, nullable=False)
    RegulatoryRiskGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<BUSINESSIMPACTFORREGULATORYRISK {self.RegulatoryRiskBusinessImpactID}>'

class BUSINESSPROCESS(Base):
    __tablename__ = 'BUSINESSPROCESS'
    __bind_key__  = 'XORCISM'

    BusinessProcessID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<BUSINESSPROCESS {self.BusinessProcessID}>'

class BUSINESSRISK(Base):
    __tablename__ = 'BUSINESSRISK'
    __bind_key__  = 'XORCISM'

    BusinessRiskID = Column(Integer, primary_key=True)
    RiskDescription = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<BUSINESSRISK {self.BusinessRiskID}>'

class BYTERUN(Base):
    __tablename__ = 'BYTERUN'
    __bind_key__  = 'XORCISM'

    ByteRunID = Column(Integer, primary_key=True)
    Offset = Column(Integer)
    File_System_Offset = Column(Integer)
    Image_Offset = Column(Integer)
    Length = Column(Integer)
    HashListID = Column(Integer)
    Byte_Run_Data = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<BYTERUN {self.ByteRunID}>'

class BYTERUNS(Base):
    __tablename__ = 'BYTERUNS'
    __bind_key__  = 'XORCISM'

    ByteRunsID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<BYTERUNS {self.ByteRunsID}>'

class BYTESRUNSBYTERUN(Base):
    __tablename__ = 'BYTESRUNSBYTERUN'
    __bind_key__  = 'XORCISM'

    ByteRunsButeRunID = Column(Integer, primary_key=True)
    ByteRunsID = Column(Integer, nullable=False)
    ByteRunID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<BYTESRUNSBYTERUN {self.ByteRunsButeRunID}>'

class CAPABILITYOBJECTIVE(Base):
    __tablename__ = 'CAPABILITYOBJECTIVE'
    __bind_key__  = 'XORCISM'

    CapabilityObjectiveID = Column(Integer, primary_key=True)
    CapabilityObjectiveGUID = Column(Text)
    ObjectiveID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CAPABILITYOBJECTIVE {self.CapabilityObjectiveID}>'

class CAPABILITYOBJECTIVERELATIONSHIP(Base):
    __tablename__ = 'CAPABILITYOBJECTIVERELATIONSHIP'
    __bind_key__  = 'XORCISM'

    CapabilityObjectiveRelashionshipID = Column(Integer, primary_key=True)
    CapabilityObjectiveRelashionshipName = Column(Text)
    CapabilityObjectiveRelashionshipDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<CAPABILITYOBJECTIVERELATIONSHIP {self.CapabilityObjectiveRelashionshipID}>'

class CATEGORY(Base):
    __tablename__ = 'CATEGORY'
    __bind_key__  = 'XORCISM'

    CategoryID = Column(Integer, primary_key=True)
    CategoryName = Column(Text, nullable=False)
    CategoryDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CATEGORY {self.CategoryID}>'

class CATEGORYDESCRIPTION(Base):
    __tablename__ = 'CATEGORYDESCRIPTION'
    __bind_key__  = 'XORCISM'

    CategoryDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CATEGORYDESCRIPTION {self.CategoryDescriptionID}>'

class CATEGORYREFERENCE(Base):
    __tablename__ = 'CATEGORYREFERENCE'
    __bind_key__  = 'XORCISM'

    CategoryReferenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CATEGORYREFERENCE {self.CategoryReferenceID}>'

class CATEGORYTAG(Base):
    __tablename__ = 'CATEGORYTAG'
    __bind_key__  = 'XORCISM'

    CategoryTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CATEGORYTAG {self.CategoryTagID}>'

class CCE(Base):
    __tablename__ = 'CCE'
    __bind_key__  = 'XORCISM'

    CCEID = Column(Integer, primary_key=True)
    cce_id = Column(Text, nullable=False)
    platform = Column(Text)
    PlatformID = Column(Integer)
    modified = Column(Text)
    description = Column(Text)
    parameter = Column(Text)
    technical_mechanism = Column(Text)
    reference = Column(Text)
    resource_id = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CreationObjectGUID = Column(Text)
    SourceID = Column(Integer)
    SourceGUID = Column(Text)
    RepositoryID = Column(Integer)
    RepositoryGUID = Column(Text)
    VocabularyID = Column(Integer)
    VocabularyGUID = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ImportanceID = Column(Integer)
    ImportanceGUID = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceLevelGUID = Column(Text)
    ConfidenceReasonID = Column(Integer)
    ConfidenceReasonGUID = Column(Text)
    TrustLevelID = Column(Integer)
    TrustLevelGUID = Column(Text)
    TrustReasonID = Column(Integer)
    TrustReasonGUID = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCE {self.CCEID}>'

class CCEFORASSET(Base):
    __tablename__ = 'CCEFORASSET'
    __bind_key__  = 'XORCISM'

    AssetCCEID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    CCEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CCEFORASSET {self.AssetCCEID}>'

class CCEFORCPE(Base):
    __tablename__ = 'CCEFORCPE'
    __bind_key__  = 'XORCISM'

    CPECCEID = Column(Integer, primary_key=True)
    cce_id = Column(Text)
    CCEID = Column(Integer, nullable=False)
    CPEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCEFORCPE {self.CPECCEID}>'

class CCEFORTHREATACTORTTP(Base):
    __tablename__ = 'CCEFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    ThreatActorTTPCCEID = Column(Integer, primary_key=True)
    ThreatActorTTPID = Column(Integer, nullable=False)
    CCEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCEFORTHREATACTORTTP {self.ThreatActorTTPCCEID}>'

class CCEPARAMETER(Base):
    __tablename__ = 'CCEPARAMETER'
    __bind_key__  = 'XORCISM'

    CCEParameterID = Column(Integer, primary_key=True)
    CCEParameterText = Column(Text, nullable=False)
    CCEParameterDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCEPARAMETER {self.CCEParameterID}>'

class CCEPARAMETERFORCCE(Base):
    __tablename__ = 'CCEPARAMETERFORCCE'
    __bind_key__  = 'XORCISM'

    CCECCEParameterID = Column(Integer, primary_key=True)
    CCEID = Column(Integer)
    CCEParameterID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCEPARAMETERFORCCE {self.CCECCEParameterID}>'

class CCEPARAMETERTAG(Base):
    __tablename__ = 'CCEPARAMETERTAG'
    __bind_key__  = 'XORCISM'

    CCEParameterTagID = Column(Integer, primary_key=True)
    CCEParameterID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCEPARAMETERTAG {self.CCEParameterTagID}>'

class CCEREFERENCE(Base):
    __tablename__ = 'CCEREFERENCE'
    __bind_key__  = 'XORCISM'

    CCEReferenceID = Column(Integer, primary_key=True)
    resource_id = Column(Text, nullable=False)
    ReferenceText = Column(Text, nullable=False)
    ReferenceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCEREFERENCE {self.CCEReferenceID}>'

class CCEREFERENCEFORCCE(Base):
    __tablename__ = 'CCEREFERENCEFORCCE'
    __bind_key__  = 'XORCISM'

    CCECCEReferenceID = Column(Integer, primary_key=True)
    CCEReferenceID = Column(Integer, nullable=False)
    CCEID = Column(Integer)
    cce_id = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCEREFERENCEFORCCE {self.CCECCEReferenceID}>'

class CCERESOURCE(Base):
    __tablename__ = 'CCERESOURCE'
    __bind_key__  = 'XORCISM'

    CCEResourceID = Column(Integer, primary_key=True)
    resource_id = Column(Text, nullable=False)
    modified = Column(Text)
    ResourceTitle = Column(Text)
    ResourcePublisher = Column(Text)
    issued = Column(Text)
    ResourceVersion = Column(Text)
    ResourceFormat = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCERESOURCE {self.CCEResourceID}>'

class CCERESOURCEAUTHOR(Base):
    __tablename__ = 'CCERESOURCEAUTHOR'
    __bind_key__  = 'XORCISM'

    CCEResourceAuthorID = Column(Integer, primary_key=True)
    CCEResourceID = Column(Integer, nullable=False)
    AuthorID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CCERESOURCEAUTHOR {self.CCEResourceAuthorID}>'

class CCERESOURCEFORCCE(Base):
    __tablename__ = 'CCERESOURCEFORCCE'
    __bind_key__  = 'XORCISM'

    CCECCEResourceID = Column(Integer, primary_key=True)
    CCEResourceID = Column(Integer, nullable=False)
    CCEID = Column(Integer)
    cce_id = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCERESOURCEFORCCE {self.CCECCEResourceID}>'

class CCERESOURCEFORCCEREFERENCE(Base):
    __tablename__ = 'CCERESOURCEFORCCEREFERENCE'
    __bind_key__  = 'XORCISM'

    CCEReferenceCCEResourceID = Column(Integer, primary_key=True)
    CCEResourceID = Column(Integer, nullable=False)
    CCEReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCERESOURCEFORCCEREFERENCE {self.CCEReferenceCCEResourceID}>'

class CCETECHNICALMECHANISM(Base):
    __tablename__ = 'CCETECHNICALMECHANISM'
    __bind_key__  = 'XORCISM'

    CCETechnicalMechanismID = Column(Integer, primary_key=True)
    TechnicalMechanismText = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CCETECHNICALMECHANISM {self.CCETechnicalMechanismID}>'

class CCETECHNICALMECHANISMFORCCE(Base):
    __tablename__ = 'CCETECHNICALMECHANISMFORCCE'
    __bind_key__  = 'XORCISM'

    CCECCETechnicalMechanismID = Column(Integer, primary_key=True)
    CCEID = Column(Integer)
    CCETechnicalMechanismID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CCETECHNICALMECHANISMFORCCE {self.CCECCETechnicalMechanismID}>'

class CCETECHNICALMECHANISMTAG(Base):
    __tablename__ = 'CCETECHNICALMECHANISMTAG'
    __bind_key__  = 'XORCISM'

    CCETechnicalMechanismTagID = Column(Integer, primary_key=True)
    CCETechnicalMechanismID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CCETECHNICALMECHANISMTAG {self.CCETechnicalMechanismTagID}>'

class CERTIFICATE(Base):
    __tablename__ = 'CERTIFICATE'
    __bind_key__  = 'XORCISM'

    CertificateID = Column(Integer, primary_key=True)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CERTIFICATE {self.CertificateID}>'

class CERTIFICATION(Base):
    __tablename__ = 'CERTIFICATION'
    __bind_key__  = 'XORCISM'

    CertificationID = Column(Integer, primary_key=True)
    CertificationGUID = Column(Text)
    CertificationAcronym = Column(Text)
    CertificationName = Column(Text, nullable=False)
    CertificationDescription = Column(Text)
    lang = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<CERTIFICATION {self.CertificationID}>'

class CERTIFICATIONSKILL(Base):
    __tablename__ = 'CERTIFICATIONSKILL'
    __bind_key__  = 'XORCISM'

    CertificationSkillID = Column(Integer, primary_key=True)
    CertificationID = Column(Integer)
    SkillID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CERTIFICATIONSKILL {self.CertificationSkillID}>'

class CHANGECONTROL(Base):
    __tablename__ = 'CHANGECONTROL'
    __bind_key__  = 'XORCISM'

    ChangeControlID = Column(Integer, primary_key=True)
    SecurityControlID = Column(Integer)

    def __repr__(self):
        return f'<CHANGECONTROL {self.ChangeControlID}>'

class CHANGELOGENTRYTYPEENUM(Base):
    __tablename__ = 'CHANGELOGENTRYTYPEENUM'
    __bind_key__  = 'XORCISM'

    ChangeLogEntryTypeEnumID = Column(Integer, primary_key=True)
    ChangeLogEntryType = Column(Text)
    ChangeLogEntryTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<CHANGELOGENTRYTYPEENUM {self.ChangeLogEntryTypeEnumID}>'

class CHANGERECORD(Base):
    __tablename__ = 'CHANGERECORD'
    __bind_key__  = 'XORCISM'

    ChangeRecordID = Column(Integer, primary_key=True)
    ChangeRecordGUID = Column(Text)
    ChangedObjectGUID = Column(Text)
    BeforeChange = Column(Text)
    AfterChange = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CHANGERECORD {self.ChangeRecordID}>'

class CHANGEREQUEST(Base):
    __tablename__ = 'CHANGEREQUEST'
    __bind_key__  = 'XORCISM'

    ChangeRequestID = Column(Integer, primary_key=True)
    ChangeRequestGUID = Column(Text)
    ImportanceID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    StatusID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CHANGEREQUEST {self.ChangeRequestID}>'

class CHANGEREQUESTAPPROVAL(Base):
    __tablename__ = 'CHANGEREQUESTAPPROVAL'
    __bind_key__  = 'XORCISM'

    ChangeRequestApprovalID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CHANGEREQUESTAPPROVAL {self.ChangeRequestApprovalID}>'

class CHANGEREQUESTCHANGERECORD(Base):
    __tablename__ = 'CHANGEREQUESTCHANGERECORD'
    __bind_key__  = 'XORCISM'

    ChangeRequestChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CHANGEREQUESTCHANGERECORD {self.ChangeRequestChangeRecordID}>'

class CHAPTER(Base):
    __tablename__ = 'CHAPTER'
    __bind_key__  = 'XORCISM'

    ChapterID = Column(Integer, primary_key=True)
    SectionID = Column(Integer)

    def __repr__(self):
        return f'<CHAPTER {self.ChapterID}>'

class CHARACTER(Base):
    __tablename__ = 'CHARACTER'
    __bind_key__  = 'XORCISM'

    CharacterID = Column(Integer, primary_key=True)
    CharacterGUID = Column(Text)
    CharacterValue = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CHARACTER {self.CharacterID}>'

class CHARACTERBLACKLIST(Base):
    __tablename__ = 'CHARACTERBLACKLIST'
    __bind_key__  = 'XORCISM'

    CharacterBlacklistID = Column(Integer, primary_key=True)
    CharacterID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<CHARACTERBLACKLIST {self.CharacterBlacklistID}>'

class CHARACTERENCODING(Base):
    __tablename__ = 'CHARACTERENCODING'
    __bind_key__  = 'XORCISM'

    CharacterEncodingID = Column(Integer, primary_key=True)
    CharacterEncodingName = Column(Text, nullable=False)
    CharacterEncodingDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<CHARACTERENCODING {self.CharacterEncodingID}>'

class CHARACTERISTIC(Base):
    __tablename__ = 'CHARACTERISTIC'
    __bind_key__  = 'XORCISM'

    CharacteristicID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CHARACTERISTIC {self.CharacteristicID}>'

class CHARACTERSET(Base):
    __tablename__ = 'CHARACTERSET'
    __bind_key__  = 'XORCISM'

    CharacterSetID = Column(Integer, primary_key=True)
    CharacterSetGUID = Column(Text)
    CharacterSetName = Column(Text)
    CharacterSetValue = Column(Text)
    CharacterSetDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CHARACTERSET {self.CharacterSetID}>'

class CHARACTERSETBLACKLIST(Base):
    __tablename__ = 'CHARACTERSETBLACKLIST'
    __bind_key__  = 'XORCISM'

    CharacterSetBlacklistID = Column(Integer, primary_key=True)
    CharacterSetID = Column(Integer)

    def __repr__(self):
        return f'<CHARACTERSETBLACKLIST {self.CharacterSetBlacklistID}>'

class CHARACTERSETWHITELIST(Base):
    __tablename__ = 'CHARACTERSETWHITELIST'
    __bind_key__  = 'XORCISM'

    CharacterSetWhitelistID = Column(Integer, primary_key=True)
    CharacterSetID = Column(Integer)

    def __repr__(self):
        return f'<CHARACTERSETWHITELIST {self.CharacterSetWhitelistID}>'

class CHARACTERWHITELIST(Base):
    __tablename__ = 'CHARACTERWHITELIST'
    __bind_key__  = 'XORCISM'

    CharacterWhitelistID = Column(Integer, primary_key=True)
    CharacterID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<CHARACTERWHITELIST {self.CharacterWhitelistID}>'

class CHARSET(Base):
    __tablename__ = 'CHARSET'
    __bind_key__  = 'XORCISM'

    CharSetID = Column(Integer, primary_key=True)
    CharacterSetID = Column(Integer)

    def __repr__(self):
        return f'<CHARSET {self.CharSetID}>'

class CHECKENUMERATION(Base):
    __tablename__ = 'CHECKENUMERATION'
    __bind_key__  = 'XORCISM'

    CheckEnumerationID = Column(Integer, primary_key=True)
    EnumerationValue = Column(Text, nullable=False)
    EnumerationDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CHECKENUMERATION {self.CheckEnumerationID}>'

class CHECKLIST(Base):
    __tablename__ = 'CHECKLIST'
    __bind_key__  = 'XORCISM'

    ChecklistID = Column(Integer, primary_key=True)
    Title = Column(Text)
    Description = Column(Text)
    AnswerSchemes = Column(Text)
    ChecklistCategoryID = Column(Integer)
    MethodologyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CHECKLIST {self.ChecklistID}>'

class CHECKLISTANSWER(Base):
    __tablename__ = 'CHECKLISTANSWER'
    __bind_key__  = 'XORCISM'

    AnswerID = Column(Integer, primary_key=True)
    QuestionID = Column(Integer)
    Answer = Column(Text)
    AnswerComments = Column(Text)
    AttachmentID = Column(Integer)
    AttachmentData = Column(LargeBinary)
    MIMEID = Column(Integer)
    AttachmentMimeType = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)

    def __repr__(self):
        return f'<CHECKLISTANSWER {self.AnswerID}>'

class CHECKLISTCATEGORY(Base):
    __tablename__ = 'CHECKLISTCATEGORY'
    __bind_key__  = 'XORCISM'

    ChecklistCategoryID = Column(Integer, primary_key=True)
    CategoryID = Column(Integer)
    Title = Column(Text)
    ChecklistCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CHECKLISTCATEGORY {self.ChecklistCategoryID}>'

class CHECKLISTCHAPTER(Base):
    __tablename__ = 'CHECKLISTCHAPTER'
    __bind_key__  = 'XORCISM'

    ChapterID = Column(Integer, primary_key=True)
    Title = Column(Text)
    ChecklistID = Column(Integer)
    ParentChapterID = Column(Integer)

    def __repr__(self):
        return f'<CHECKLISTCHAPTER {self.ChapterID}>'

class CHECKLISTQUESTION(Base):
    __tablename__ = 'CHECKLISTQUESTION'
    __bind_key__  = 'XORCISM'

    QuestionID = Column(Integer, primary_key=True)
    QuestionRefID = Column(Text)
    Title = Column(Text)
    LongName = Column(Text)
    Description = Column(Text)
    Target = Column(Text)
    ChapterID = Column(Integer)
    Tags = Column(Text)
    lang = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CHECKLISTQUESTION {self.QuestionID}>'

class CHECKLISTQUESTIONCATEGORY(Base):
    __tablename__ = 'CHECKLISTQUESTIONCATEGORY'
    __bind_key__  = 'XORCISM'

    QuestionCategoryID = Column(Integer, primary_key=True)
    QuestionID = Column(Integer, nullable=False)
    CategoryID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CHECKLISTQUESTIONCATEGORY {self.QuestionCategoryID}>'

class CHECKLISTQUESTIONSECURITYCONTROL(Base):
    __tablename__ = 'CHECKLISTQUESTIONSECURITYCONTROL'
    __bind_key__  = 'XORCISM'

    QuestionSecurityControlID = Column(Integer, primary_key=True)
    QuestionID = Column(Integer, nullable=False)
    SecurityControlID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CHECKLISTQUESTIONSECURITYCONTROL {self.QuestionSecurityControlID}>'

class CIAIMPACTFORATTACKPATTERN(Base):
    __tablename__ = 'CIAIMPACTFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternCIAImpactID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    AttackPatternGUID = Column(Text)
    Confidentiality_Impact = Column(Text)
    Integrity_Impact = Column(Text)
    Availability_Impact = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CIAIMPACTFORATTACKPATTERN {self.AttackPatternCIAImpactID}>'

class CLASSIFICATION(Base):
    __tablename__ = 'CLASSIFICATION'
    __bind_key__  = 'XORCISM'

    ClassificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CLASSIFICATION {self.ClassificationID}>'

class CLASSIFICATIONCATEGORY(Base):
    __tablename__ = 'CLASSIFICATIONCATEGORY'
    __bind_key__  = 'XORCISM'

    ClassificationCategoryID = Column(Integer, primary_key=True)
    ClassificationCategoryGUID = Column(Text)
    ClassificationCategoryName = Column(Text)
    ClassificationCategoryDescription = Column(Text)
    CategoryID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CLASSIFICATIONCATEGORY {self.ClassificationCategoryID}>'

class CLASSIFICATIONLEVEL(Base):
    __tablename__ = 'CLASSIFICATIONLEVEL'
    __bind_key__  = 'XORCISM'

    ClassificationLevelID = Column(Integer, primary_key=True)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CLASSIFICATIONLEVEL {self.ClassificationLevelID}>'

class CLASSIFICATIONRESTRICTION(Base):
    __tablename__ = 'CLASSIFICATIONRESTRICTION'
    __bind_key__  = 'XORCISM'

    ClassificationRestrictionID = Column(Integer, primary_key=True)
    ClassificationID = Column(Integer, nullable=False)
    RestrictionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CLASSIFICATIONRESTRICTION {self.ClassificationRestrictionID}>'

class CLUSTEREDGENODEPAIR(Base):
    __tablename__ = 'CLUSTEREDGENODEPAIR'
    __bind_key__  = 'XORCISM'

    ClusterEdgeNodePairID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CLUSTEREDGENODEPAIR {self.ClusterEdgeNodePairID}>'

class COASTAGE(Base):
    __tablename__ = 'COASTAGE'
    __bind_key__  = 'XORCISM'

    COAStageID = Column(Integer, primary_key=True)
    COAStageGUID = Column(Text)
    COAStageName = Column(Text, nullable=False)
    COAStageDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COASTAGE {self.COAStageID}>'

class CODE(Base):
    __tablename__ = 'CODE'
    __bind_key__  = 'XORCISM'

    CodeID = Column(Integer, primary_key=True)
    CodeGUID = Column(Text)
    Block_Nature = Column(Text)
    ScriptID = Column(Integer)
    Description = Column(Text)
    Type = Column(Text)
    CodeTypeID = Column(Integer)
    Purpose = Column(Text)
    CodePurposeID = Column(Integer)
    Code_Language = Column(Text)
    CodeLanguageID = Column(Integer)
    TargetedPlatformsID = Column(Integer)
    Processor_Family = Column(Text)
    Discovery_Method = Column(Text)
    MeasureSourceID = Column(Integer)
    Start_Address = Column(Text)
    MemoryAddressID = Column(Integer)
    Code_Segment = Column(Text)
    Code_Segment_XOR = Column(Text)
    CodeSegmentXORID = Column(Integer)
    DigitalSignaturesID = Column(Integer)
    Extracted_Features = Column(Text)
    ExtractedFeaturesID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CODE {self.CodeID}>'

class CODEFUNCTION(Base):
    __tablename__ = 'CODEFUNCTION'
    __bind_key__  = 'XORCISM'

    CodeFunctionID = Column(Integer, primary_key=True)
    CodeFunctionGUID = Column(Text)
    CodeID = Column(Integer)
    CodeGUID = Column(Text)
    FunctionID = Column(Integer)
    FunctionGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    LastCheckedDate = Column(Text)

    def __repr__(self):
        return f'<CODEFUNCTION {self.CodeFunctionID}>'

class CODELANGUAGE(Base):
    __tablename__ = 'CODELANGUAGE'
    __bind_key__  = 'XORCISM'

    CodeLanguageID = Column(Integer, primary_key=True)
    LanguageID = Column(Integer)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<CODELANGUAGE {self.CodeLanguageID}>'

class CODELANGUAGES(Base):
    __tablename__ = 'CODELANGUAGES'
    __bind_key__  = 'XORCISM'

    CodeLanguagesID = Column(Integer, primary_key=True)
    CodeID = Column(Integer, nullable=False)
    LanguageID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CodeLanguageDescription = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    DiscoveryMethodID = Column(Integer)
    DiscoveryToolID = Column(Integer)

    def __repr__(self):
        return f'<CODELANGUAGES {self.CodeLanguagesID}>'

class CODELICENSE(Base):
    __tablename__ = 'CODELICENSE'
    __bind_key__  = 'XORCISM'

    CodeLicenseID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CODELICENSE {self.CodeLicenseID}>'

class CODELINE(Base):
    __tablename__ = 'CODELINE'
    __bind_key__  = 'XORCISM'

    CodeLineID = Column(Integer, primary_key=True)
    CodeLineGUID = Column(Text)
    LineOfCode = Column(Text)
    KnownVulnerable = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<CODELINE {self.CodeLineID}>'

class CODELINEFUNCTION(Base):
    __tablename__ = 'CODELINEFUNCTION'
    __bind_key__  = 'XORCISM'

    CodeLineFunctionID = Column(Integer, primary_key=True)
    CodeLineID = Column(Integer, nullable=False)
    FunctionID = Column(Integer)
    LanguageFunctionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<CODELINEFUNCTION {self.CodeLineFunctionID}>'

class CODELINES(Base):
    __tablename__ = 'CODELINES'
    __bind_key__  = 'XORCISM'

    CodeLinesID = Column(Integer, primary_key=True)
    CodeID = Column(Integer, nullable=False)
    CodeLineID = Column(Integer, nullable=False)
    ordinal_position = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CODELINES {self.CodeLinesID}>'

class CODEPROCESSORTYPE(Base):
    __tablename__ = 'CODEPROCESSORTYPE'
    __bind_key__  = 'XORCISM'

    CodeProcessorTypeID = Column(Integer, primary_key=True)
    CodeID = Column(Integer, nullable=False)
    ProcessorTypeID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<CODEPROCESSORTYPE {self.CodeProcessorTypeID}>'

class CODEPURPOSE(Base):
    __tablename__ = 'CODEPURPOSE'
    __bind_key__  = 'XORCISM'

    CodePurposeID = Column(Integer, primary_key=True)
    CodePurposeEnumID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CODEPURPOSE {self.CodePurposeID}>'

class CODEPURPOSEENUM(Base):
    __tablename__ = 'CODEPURPOSEENUM'
    __bind_key__  = 'XORCISM'

    CodePurposeEnumID = Column(Integer, primary_key=True)
    CodePurpose = Column(Text)
    CodePurposeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<CODEPURPOSEENUM {self.CodePurposeEnumID}>'

class CODESEGMENTXOR(Base):
    __tablename__ = 'CODESEGMENTXOR'
    __bind_key__  = 'XORCISM'

    CodeSegmentXORID = Column(Integer, primary_key=True)
    xor_pattern = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<CODESEGMENTXOR {self.CodeSegmentXORID}>'

class CODETYPE(Base):
    __tablename__ = 'CODETYPE'
    __bind_key__  = 'XORCISM'

    CodeTypeID = Column(Integer, primary_key=True)
    CodeTypeEnumID = Column(Integer)

    def __repr__(self):
        return f'<CODETYPE {self.CodeTypeID}>'

class CODETYPEENUM(Base):
    __tablename__ = 'CODETYPEENUM'
    __bind_key__  = 'XORCISM'

    CodeTypeEnumID = Column(Integer, primary_key=True)
    CodeType = Column(Text)
    CodeTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<CODETYPEENUM {self.CodeTypeEnumID}>'

class COLLECTIONMETHOD(Base):
    __tablename__ = 'COLLECTIONMETHOD'
    __bind_key__  = 'XORCISM'

    CollectionMethodID = Column(Integer, primary_key=True)
    CollectionMethodName = Column(Text)
    MeasureSourceID = Column(Integer)
    CollectionMethodDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COLLECTIONMETHOD {self.CollectionMethodID}>'

class COLLECTIONMETHODDESCRIPTION(Base):
    __tablename__ = 'COLLECTIONMETHODDESCRIPTION'
    __bind_key__  = 'XORCISM'

    CollectionMethodDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COLLECTIONMETHODDESCRIPTION {self.CollectionMethodDescriptionID}>'

class COLLECTIONMETHODREFERENCE(Base):
    __tablename__ = 'COLLECTIONMETHODREFERENCE'
    __bind_key__  = 'XORCISM'

    CollectionMethodReferenceID = Column(Integer, primary_key=True)
    CollectionMethodID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CollectionMethodDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<COLLECTIONMETHODREFERENCE {self.CollectionMethodReferenceID}>'

class COLLECTIONMETHODTAG(Base):
    __tablename__ = 'COLLECTIONMETHODTAG'
    __bind_key__  = 'XORCISM'

    CollectionMethodTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COLLECTIONMETHODTAG {self.CollectionMethodTagID}>'

class COLSTAGE(Base):
    __tablename__ = 'COLSTAGE'
    __bind_key__  = 'XORCISM'

    COLStageID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COLSTAGE {self.COLStageID}>'

class COMMAND(Base):
    __tablename__ = 'COMMAND'
    __bind_key__  = 'XORCISM'

    CommandID = Column(Integer, primary_key=True)
    CommandName = Column(Text, nullable=False)
    CommandDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    KnownVulnerable = Column(Integer)

    def __repr__(self):
        return f'<COMMAND {self.CommandID}>'

class COMMANDANDCONTROLPROPERTIES(Base):
    __tablename__ = 'COMMANDANDCONTROLPROPERTIES'
    __bind_key__  = 'XORCISM'

    CommandandControlPropertiesID = Column(Integer, primary_key=True)
    CommandandControlPropertiesName = Column(Text)
    CommandandControlPropertiesDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<COMMANDANDCONTROLPROPERTIES {self.CommandandControlPropertiesID}>'

class COMMANDANDCONTROLSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'COMMANDANDCONTROLSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    CommandandControlStrategicObjectiveID = Column(Integer, primary_key=True)
    CommandandControlStrategicObjectiveName = Column(Text)
    CommandandControlStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COMMANDANDCONTROLSTRATEGICOBJECTIVE {self.CommandandControlStrategicObjectiveID}>'

class COMMANDANDCONTROLTACTICALOBJECTIVE(Base):
    __tablename__ = 'COMMANDANDCONTROLTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    CommandandControlTacticalObjectiveID = Column(Integer, primary_key=True)
    CommandandControlTacticalObjectiveName = Column(Text)
    CommandandControlTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COMMANDANDCONTROLTACTICALOBJECTIVE {self.CommandandControlTacticalObjectiveID}>'

class COMMANDS(Base):
    __tablename__ = 'COMMANDS'
    __bind_key__  = 'XORCISM'

    CommandsID = Column(Integer, primary_key=True)
    ScriptName = Column(Text, nullable=False)
    CommandsDescription = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<COMMANDS {self.CommandsID}>'

class COMMONCAPABILITYPROPERTIES(Base):
    __tablename__ = 'COMMONCAPABILITYPROPERTIES'
    __bind_key__  = 'XORCISM'

    CommonCapabilityPropertiesID = Column(Integer, primary_key=True)
    CommonCapabilityPropertiesName = Column(Text)
    CommonCapabilityPropertiesDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COMMONCAPABILITYPROPERTIES {self.CommonCapabilityPropertiesID}>'

class COMPLIANCE(Base):
    __tablename__ = 'COMPLIANCE'
    __bind_key__  = 'XORCISM'

    ComplianceID = Column(Integer, primary_key=True)
    ComplianceGUID = Column(Text)
    ComplianceName = Column(Text)
    ComplianceVersion = Column(Text)
    ComplianceDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ImportanceID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<COMPLIANCE {self.ComplianceID}>'

class COMPLIANCECATEGORY(Base):
    __tablename__ = 'COMPLIANCECATEGORY'
    __bind_key__  = 'XORCISM'

    ComplianceCategoryID = Column(Integer, primary_key=True)
    ComplianceCategoryName = Column(Text)
    ComplianceCategoryDescription = Column(Text)
    ComplianceID = Column(Integer)
    ParentCategoryID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<COMPLIANCECATEGORY {self.ComplianceCategoryID}>'

class COMPLIANCECERTIFICATION(Base):
    __tablename__ = 'COMPLIANCECERTIFICATION'
    __bind_key__  = 'XORCISM'

    ComplianceCertificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COMPLIANCECERTIFICATION {self.ComplianceCertificationID}>'

class COMPLIANCECHANGERECORD(Base):
    __tablename__ = 'COMPLIANCECHANGERECORD'
    __bind_key__  = 'XORCISM'

    ComplianceChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COMPLIANCECHANGERECORD {self.ComplianceChangeRecordID}>'

class COMPLIANCEDESCRIPTION(Base):
    __tablename__ = 'COMPLIANCEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ComplianceDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COMPLIANCEDESCRIPTION {self.ComplianceDescriptionID}>'

class COMPLIANCEREFERENCE(Base):
    __tablename__ = 'COMPLIANCEREFERENCE'
    __bind_key__  = 'XORCISM'

    ComplianceReferenceID = Column(Integer, primary_key=True)
    ComplianceID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ComplianceReferenceDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<COMPLIANCEREFERENCE {self.ComplianceReferenceID}>'

class COMPLIANCETAG(Base):
    __tablename__ = 'COMPLIANCETAG'
    __bind_key__  = 'XORCISM'

    ComplianceTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COMPLIANCETAG {self.ComplianceTagID}>'

class COMPONENT(Base):
    __tablename__ = 'COMPONENT'
    __bind_key__  = 'XORCISM'

    ComponentID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COMPONENT {self.ComponentID}>'

class COMPRESSION(Base):
    __tablename__ = 'COMPRESSION'
    __bind_key__  = 'XORCISM'

    CompressionID = Column(Integer, primary_key=True)
    compression_mechanism = Column(Text)
    compression_mechanism_ref = Column(Text)
    CompressionDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COMPRESSION {self.CompressionID}>'

class COMPRESSIONMECHANISM(Base):
    __tablename__ = 'COMPRESSIONMECHANISM'
    __bind_key__  = 'XORCISM'

    CompressionMechanismID = Column(Integer, primary_key=True)
    MechanismID = Column(Integer)

    def __repr__(self):
        return f'<COMPRESSIONMECHANISM {self.CompressionMechanismID}>'

class COMPRESSIONMECHANISMDESCRIPTION(Base):
    __tablename__ = 'COMPRESSIONMECHANISMDESCRIPTION'
    __bind_key__  = 'XORCISM'

    CompressionMechanismDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COMPRESSIONMECHANISMDESCRIPTION {self.CompressionMechanismDescriptionID}>'

class COMPRESSIONMECHANISMTAG(Base):
    __tablename__ = 'COMPRESSIONMECHANISMTAG'
    __bind_key__  = 'XORCISM'

    CompressionMechanismTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COMPRESSIONMECHANISMTAG {self.CompressionMechanismTagID}>'

class COMPRESSIONREFERENCE(Base):
    __tablename__ = 'COMPRESSIONREFERENCE'
    __bind_key__  = 'XORCISM'

    CompressionReferenceID = Column(Integer, primary_key=True)
    CompressionID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<COMPRESSIONREFERENCE {self.CompressionReferenceID}>'

class CONCATFUNCTION(Base):
    __tablename__ = 'CONCATFUNCTION'
    __bind_key__  = 'XORCISM'

    ConcatFunctionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CONCATFUNCTION {self.ConcatFunctionID}>'

class CONDITION(Base):
    __tablename__ = 'CONDITION'
    __bind_key__  = 'XORCISM'

    ConditionID = Column(Integer, primary_key=True)
    ConditionName = Column(Text, nullable=False)
    ConditionDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CONDITION {self.ConditionID}>'

class CONDITIONAPPLICATION(Base):
    __tablename__ = 'CONDITIONAPPLICATION'
    __bind_key__  = 'XORCISM'

    ConditionApplicationID = Column(Integer, primary_key=True)
    ConditionApplicationName = Column(Text, nullable=False)
    ConditionApplicationDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CONDITIONAPPLICATION {self.ConditionApplicationID}>'

class CONFIDENCELEVEL(Base):
    __tablename__ = 'CONFIDENCELEVEL'
    __bind_key__  = 'XORCISM'

    ConfidenceLevelID = Column(Integer, primary_key=True)
    ConfidenceLevelGUID = Column(Text)
    ConfidenceLevelName = Column(Text, nullable=False)
    ConfidenceLevelDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CONFIDENCELEVEL {self.ConfidenceLevelID}>'

class CONFIDENCEREASON(Base):
    __tablename__ = 'CONFIDENCEREASON'
    __bind_key__  = 'XORCISM'

    ConfidenceReasonID = Column(Integer, primary_key=True)
    ConfidenceReasonName = Column(Text)
    ConfidenceReasonDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CONFIDENCEREASON {self.ConfidenceReasonID}>'

class CONFIDENTIALITYLEVEL(Base):
    __tablename__ = 'CONFIDENTIALITYLEVEL'
    __bind_key__  = 'XORCISM'

    ConfidentialityLevelID = Column(Integer, primary_key=True)
    ClassificationID = Column(Integer)
    VocabularyID = Column(Integer)
    ConfidentialityLevelName = Column(Text)
    ConfidentialityLevelDescription = Column(Text)

    def __repr__(self):
        return f'<CONFIDENTIALITYLEVEL {self.ConfidentialityLevelID}>'

class CONNECTION(Base):
    __tablename__ = 'CONNECTION'
    __bind_key__  = 'XORCISM'

    ConnectionID = Column(Integer, primary_key=True)
    ipaddressIPv4 = Column(Text)
    ipaddressIPv6 = Column(Text)
    macaddress = Column(Text)
    subnetmaskIPv4 = Column(Text)
    subnetmaskIPv6 = Column(Text)
    defaultrouteIPv4 = Column(Text)
    defaultrouteIPv6 = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CONNECTION {self.ConnectionID}>'

class CONNECTIONFORASSET(Base):
    __tablename__ = 'CONNECTIONFORASSET'
    __bind_key__  = 'XORCISM'

    AssetConnectionID = Column(Integer, primary_key=True)
    AssetConnectionGUID = Column(Text)
    ConnectionID = Column(Integer, nullable=False)
    ConnectionGUID = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    LastCheckedDate = Column(Text)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<CONNECTIONFORASSET {self.AssetConnectionID}>'

class CONTACT(Base):
    __tablename__ = 'CONTACT'
    __bind_key__  = 'XORCISM'

    ContactID = Column(Integer, primary_key=True)
    ContactTypeID = Column(Integer)

    def __repr__(self):
        return f'<CONTACT {self.ContactID}>'

class CONTACTTYPE(Base):
    __tablename__ = 'CONTACTTYPE'
    __bind_key__  = 'XORCISM'

    ContactTypeID = Column(Integer, primary_key=True)
    ContactTypeGUID = Column(Text)
    ContactTypeName = Column(Text, nullable=False)
    ContactTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CONTACTTYPE {self.ContactTypeID}>'

class CONTENTENUMERATION(Base):
    __tablename__ = 'CONTENTENUMERATION'
    __bind_key__  = 'XORCISM'

    ContentEnumerationID = Column(Integer, primary_key=True)
    ContentEnumerationValue = Column(Text, nullable=False)
    ContentEnumerationDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CONTENTENUMERATION {self.ContentEnumerationID}>'

class CONTEXT(Base):
    __tablename__ = 'CONTEXT'
    __bind_key__  = 'XORCISM'

    ContextID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CONTEXT {self.ContextID}>'

class CONTROL(Base):
    __tablename__ = 'CONTROL'
    __bind_key__  = 'XORCISM'

    ControlID = Column(Integer, primary_key=True)
    ControlGUID = Column(Text)
    ControlName = Column(Text)
    ControlDescription = Column(Text)
    ReliabilityID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ISO = Column(Text)
    NIST = Column(Text)
    CIS = Column(Text)
    Minimal = Column(Text)
    Balanced = Column(Text)
    Comprehensive = Column(Text)

    def __repr__(self):
        return f'<CONTROL {self.ControlID}>'

class CONTROLCATEGORY(Base):
    __tablename__ = 'CONTROLCATEGORY'
    __bind_key__  = 'XORCISM'

    ControlCategoryID = Column(Integer, primary_key=True)
    ControlCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CONTROLCATEGORY {self.ControlCategoryID}>'

class CONTROLDESCRIPTION(Base):
    __tablename__ = 'CONTROLDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ControlDescriptionID = Column(Integer, primary_key=True)
    ControlID = Column(Integer)
    ControlGUID = Column(Text)
    DescriptionID = Column(Integer)
    DescriptionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CONTROLDESCRIPTION {self.ControlDescriptionID}>'

class CONTROLREFERENCE(Base):
    __tablename__ = 'CONTROLREFERENCE'
    __bind_key__  = 'XORCISM'

    ControlReferenceID = Column(Integer, primary_key=True)
    ControlID = Column(Integer)
    ControlGUID = Column(Text)
    ReferenceID = Column(Integer)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CONTROLREFERENCE {self.ControlReferenceID}>'

class CONTROLSTRENGTH(Base):
    __tablename__ = 'CONTROLSTRENGTH'
    __bind_key__  = 'XORCISM'

    ControlStrengthID = Column(Integer, primary_key=True)
    ControlStrengthGUID = Column(Text)
    ControlStrengthName = Column(Text)
    ControlStrengthDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CONTROLSTRENGTH {self.ControlStrengthID}>'

class CONTROLTAG(Base):
    __tablename__ = 'CONTROLTAG'
    __bind_key__  = 'XORCISM'

    ControlTagID = Column(Integer, primary_key=True)
    ControlID = Column(Integer)
    ControlGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CONTROLTAG {self.ControlTagID}>'

class COOKIE(Base):
    __tablename__ = 'COOKIE'
    __bind_key__  = 'XORCISM'

    CookieID = Column(Integer, primary_key=True)
    CookieGUID = Column(Text)
    CookieNameValue = Column(Text)
    CookieNameID = Column(Integer)
    CookieNameGUID = Column(Text)
    CookieValue = Column(Text)
    CookieDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COOKIE {self.CookieID}>'

class COOKIEAPPLICATION(Base):
    __tablename__ = 'COOKIEAPPLICATION'
    __bind_key__  = 'XORCISM'

    CookieApplicationID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer)
    ApplicationGUID = Column(Text)
    CookieApplicationRelationship = Column(Text)
    CookieApplicationDescription = Column(Text)
    CookieID = Column(Integer)
    CookieGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<COOKIEAPPLICATION {self.CookieApplicationID}>'

class COOKIECPE(Base):
    __tablename__ = 'COOKIECPE'
    __bind_key__  = 'XORCISM'

    CookieCPEID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COOKIECPE {self.CookieCPEID}>'

class COOKIEFILE(Base):
    __tablename__ = 'COOKIEFILE'
    __bind_key__  = 'XORCISM'

    CookieFileID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COOKIEFILE {self.CookieFileID}>'

class COOKIENAME(Base):
    __tablename__ = 'COOKIENAME'
    __bind_key__  = 'XORCISM'

    CookieNameID = Column(Integer, primary_key=True)
    CookieNameGUID = Column(Text)
    CookieNameValue = Column(Text)
    CookieNameDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COOKIENAME {self.CookieNameID}>'

class COOKIENAMEAPPLICATION(Base):
    __tablename__ = 'COOKIENAMEAPPLICATION'
    __bind_key__  = 'XORCISM'

    CookieNameApplicationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COOKIENAMEAPPLICATION {self.CookieNameApplicationID}>'

class COOKIENAMEORGANISATION(Base):
    __tablename__ = 'COOKIENAMEORGANISATION'
    __bind_key__  = 'XORCISM'

    CookieNameOrganisationID = Column(Integer, primary_key=True)
    OrganisationID = Column(Integer)
    OrganisationGUID = Column(Text)
    CookieNameOrganisationRelationship = Column(Text)
    CookieNameOrganisationDescription = Column(Text)
    CookieNameID = Column(Integer)
    CookieNameGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COOKIENAMEORGANISATION {self.CookieNameOrganisationID}>'

class COOKIENAMEPRODUCT(Base):
    __tablename__ = 'COOKIENAMEPRODUCT'
    __bind_key__  = 'XORCISM'

    CookieNameProductID = Column(Integer, primary_key=True)
    CookieNameID = Column(Integer)
    ProductID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COOKIENAMEPRODUCT {self.CookieNameProductID}>'

class COOKIEPERSON(Base):
    __tablename__ = 'COOKIEPERSON'
    __bind_key__  = 'XORCISM'

    CookiePersonID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COOKIEPERSON {self.CookiePersonID}>'

class COOKIESECURITYCONTROL(Base):
    __tablename__ = 'COOKIESECURITYCONTROL'
    __bind_key__  = 'XORCISM'

    CookieSecurityControlID = Column(Integer, primary_key=True)
    CookieID = Column(Integer)
    CookieGUID = Column(Text)
    CookieSecurityControlRelationship = Column(Text)
    CookieSecurityControlDescription = Column(Text)
    SecurityControlID = Column(Integer)
    SecurityControlGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<COOKIESECURITYCONTROL {self.CookieSecurityControlID}>'

class COUNTFUNCTION(Base):
    __tablename__ = 'COUNTFUNCTION'
    __bind_key__  = 'XORCISM'

    CountFunctionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COUNTFUNCTION {self.CountFunctionID}>'

class COUNTRY(Base):
    __tablename__ = 'COUNTRY'
    __bind_key__  = 'XORCISM'

    CountryID = Column(Integer, primary_key=True)
    CountryGUID = Column(Text)
    CountryCode = Column(Text, nullable=False)
    CountryName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromdate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<COUNTRY {self.CountryID}>'

class COUNTRYLAW(Base):
    __tablename__ = 'COUNTRYLAW'
    __bind_key__  = 'XORCISM'

    CountryLawID = Column(Integer, primary_key=True)
    CountryID = Column(Integer, nullable=False)
    LawID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<COUNTRYLAW {self.CountryLawID}>'

class COUNTRYLOCALE(Base):
    __tablename__ = 'COUNTRYLOCALE'
    __bind_key__  = 'XORCISM'

    CountryLocaleID = Column(Integer, primary_key=True)
    CountryID = Column(Integer, nullable=False)
    LocaleID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<COUNTRYLOCALE {self.CountryLocaleID}>'

class COUNTRYTELEPHONE(Base):
    __tablename__ = 'COUNTRYTELEPHONE'
    __bind_key__  = 'XORCISM'

    CountryTelephoneID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COUNTRYTELEPHONE {self.CountryTelephoneID}>'

class COUNTRYZONE(Base):
    __tablename__ = 'COUNTRYZONE'
    __bind_key__  = 'XORCISM'

    CountryZoneID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COUNTRYZONE {self.CountryZoneID}>'

class COURSEOFACTION(Base):
    __tablename__ = 'COURSEOFACTION'
    __bind_key__  = 'XORCISM'

    CourseOfActionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COURSEOFACTION {self.CourseOfActionID}>'

class COURSEOFACTIONTYPE(Base):
    __tablename__ = 'COURSEOFACTIONTYPE'
    __bind_key__  = 'XORCISM'

    CourseOfActionTypeID = Column(Integer, primary_key=True)
    CourseOfActionTypeGUID = Column(Text)
    CourseOfActionTypeName = Column(Text)
    CourseOfActionTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<COURSEOFACTIONTYPE {self.CourseOfActionTypeID}>'

class COURSEOFLAW(Base):
    __tablename__ = 'COURSEOFLAW'
    __bind_key__  = 'XORCISM'

    CourseOfLawID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<COURSEOFLAW {self.CourseOfLawID}>'

class CPE(Base):
    __tablename__ = 'CPE'
    __bind_key__  = 'XORCISM'

    CPEID = Column(Integer, primary_key=True)
    CPEName = Column(Text, nullable=False)
    CPETitle = Column(Text)
    NVDID = Column(Integer)
    ModificationDate = Column(Text)
    Status = Column(Text)
    CPEDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPE {self.CPEID}>'

class CPEBANNER(Base):
    __tablename__ = 'CPEBANNER'
    __bind_key__  = 'XORCISM'

    CPEBannerID = Column(Integer, primary_key=True)
    CPEID = Column(Integer, nullable=False)
    BannerID = Column(Integer, nullable=False)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    RepositoryID = Column(Integer)
    CreationObjectID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEBANNER {self.CPEBannerID}>'

class CPEBLACKLIST(Base):
    __tablename__ = 'CPEBLACKLIST'
    __bind_key__  = 'XORCISM'

    CPEBlacklistID = Column(Integer, primary_key=True)
    CPEID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)
    AssetID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEBLACKLIST {self.CPEBlacklistID}>'

class CPEFILELIST(Base):
    __tablename__ = 'CPEFILELIST'
    __bind_key__  = 'XORCISM'

    CPEFileListID = Column(Integer, primary_key=True)
    CPEID = Column(Integer)
    CPEName = Column(Text)
    CPEFileListRelationship = Column(Text)
    CPEFileListDescription = Column(Text)
    FileListID = Column(Integer)
    FileListGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CPEFILELIST {self.CPEFileListID}>'

class CPEFORAPPLICATION(Base):
    __tablename__ = 'CPEFORAPPLICATION'
    __bind_key__  = 'XORCISM'

    ApplicationCPEID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    CPEID = Column(Integer, nullable=False)
    CreationDate = Column(Text)
    BLOB = Column(Text)
    LastCheckedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<CPEFORAPPLICATION {self.ApplicationCPEID}>'

class CPEFORASSET(Base):
    __tablename__ = 'CPEFORASSET'
    __bind_key__  = 'XORCISM'

    AssetCPEID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    CPEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<CPEFORASSET {self.AssetCPEID}>'

class CPEFORFIXACTION(Base):
    __tablename__ = 'CPEFORFIXACTION'
    __bind_key__  = 'XORCISM'

    FixActionCPEID = Column(Integer, primary_key=True)
    CPEID = Column(Integer, nullable=False)
    FixActionID = Column(Integer, nullable=False)
    relationshiptype = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEFORFIXACTION {self.FixActionCPEID}>'

class CPEFORORGANISATION(Base):
    __tablename__ = 'CPEFORORGANISATION'
    __bind_key__  = 'XORCISM'

    OrganisationCPEID = Column(Integer, primary_key=True)
    OrganisationID = Column(Integer, nullable=False)
    CPEID = Column(Integer, nullable=False)
    Usage = Column(Text)
    Description = Column(Text)
    CreatedDate = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    BLOB = Column(Text)
    LastCheckedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEFORORGANISATION {self.OrganisationCPEID}>'

class CPEFORPLATFORM(Base):
    __tablename__ = 'CPEFORPLATFORM'
    __bind_key__  = 'XORCISM'

    PlatformCPEID = Column(Integer, primary_key=True)
    PlatformID = Column(Integer, nullable=False)
    CPEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEFORPLATFORM {self.PlatformCPEID}>'

class CPEFORPRODUCT(Base):
    __tablename__ = 'CPEFORPRODUCT'
    __bind_key__  = 'XORCISM'

    ProductCPEID = Column(Integer, primary_key=True)
    ProductID = Column(Integer, nullable=False)
    ProductGUID = Column(Text)
    CPEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEFORPRODUCT {self.ProductCPEID}>'

class CPEFORTOOL(Base):
    __tablename__ = 'CPEFORTOOL'
    __bind_key__  = 'XORCISM'

    ToolCPEID = Column(Integer, primary_key=True)
    ToolID = Column(Integer, nullable=False)
    ToolGUID = Column(Text)
    CPEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEFORTOOL {self.ToolCPEID}>'

class CPEGOOGLEDORK(Base):
    __tablename__ = 'CPEGOOGLEDORK'
    __bind_key__  = 'XORCISM'

    CPEGoogleDorkID = Column(Integer, primary_key=True)
    CPEID = Column(Integer, nullable=False)
    GoogleDorkID = Column(Integer, nullable=False)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEGOOGLEDORK {self.CPEGoogleDorkID}>'

class CPELOGICALTEST(Base):
    __tablename__ = 'CPELOGICALTEST'
    __bind_key__  = 'XORCISM'

    CPELogicalTestID = Column(Integer, primary_key=True)
    negate = Column(Integer)
    OperatorEnumerationID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CPELOGICALTEST {self.CPELogicalTestID}>'

class CPEPATCH(Base):
    __tablename__ = 'CPEPATCH'
    __bind_key__  = 'XORCISM'

    CPEPatchID = Column(Integer, primary_key=True)
    CPEID = Column(Integer)
    PatchID = Column(Integer)
    PatchGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEPATCH {self.CPEPatchID}>'

class CPEPORT(Base):
    __tablename__ = 'CPEPORT'
    __bind_key__  = 'XORCISM'

    CPEPortID = Column(Integer, primary_key=True)
    CPEID = Column(Integer, nullable=False)
    PortID = Column(Integer, nullable=False)
    CPEPortUsage = Column(Text)
    CPEPortDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEPORT {self.CPEPortID}>'

class CPEREFERENCE(Base):
    __tablename__ = 'CPEREFERENCE'
    __bind_key__  = 'XORCISM'

    CPEReferenceID = Column(Integer, primary_key=True)
    CPEID = Column(Integer)
    ReferenceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEREFERENCE {self.CPEReferenceID}>'

class CPETAG(Base):
    __tablename__ = 'CPETAG'
    __bind_key__  = 'XORCISM'

    CPETagID = Column(Integer, primary_key=True)
    CPEID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPETAG {self.CPETagID}>'

class CPETECHNOLOGY(Base):
    __tablename__ = 'CPETECHNOLOGY'
    __bind_key__  = 'XORCISM'

    CPETechnologyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CPETECHNOLOGY {self.CPETechnologyID}>'

class CPEURI(Base):
    __tablename__ = 'CPEURI'
    __bind_key__  = 'XORCISM'

    CPEURIID = Column(Integer, primary_key=True)
    CPEID = Column(Integer, nullable=False)
    URIObjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CPEURI {self.CPEURIID}>'

class CPEWHITELIST(Base):
    __tablename__ = 'CPEWHITELIST'
    __bind_key__  = 'XORCISM'

    CPEWhitelistID = Column(Integer, primary_key=True)
    CPEID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer)
    OrganisationGUID = Column(Text)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CPEWHITELIST {self.CPEWhitelistID}>'

class CREATIONOBJECT(Base):
    __tablename__ = 'CREATIONOBJECT'
    __bind_key__  = 'XORCISM'

    CreationObjectID = Column(Integer, primary_key=True)
    CreationObjectGUID = Column(Text)
    ObjectID = Column(Integer)
    RecordGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    OrganisationID = Column(Integer)
    OrganisationGUID = Column(Text)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    AccountID = Column(Integer)
    AccountGUID = Column(Text)
    UserID = Column(Integer)
    UserGUID = Column(Text)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    SensorID = Column(Integer)
    SensorGUID = Column(Text)
    ToolID = Column(Integer)
    ToolGUID = Column(Text)
    ToolFunctionID = Column(Integer)
    ToolFunctionGUID = Column(Text)
    ToolCodeID = Column(Integer)
    ToolCodeGUID = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)

    def __repr__(self):
        return f'<CREATIONOBJECT {self.CreationObjectID}>'

class CREATIONOBJECTHASH(Base):
    __tablename__ = 'CREATIONOBJECTHASH'
    __bind_key__  = 'XORCISM'

    CreationObjectHashID = Column(Integer, primary_key=True)
    CreationObjectID = Column(Integer, nullable=False)
    CreationObjectGUID = Column(Text)
    CreationObjectHashValue = Column(Text)
    isEncrypted = Column(Integer)
    CreationDate = Column(Text)

    def __repr__(self):
        return f'<CREATIONOBJECTHASH {self.CreationObjectHashID}>'

class CREDENTIAL(Base):
    __tablename__ = 'CREDENTIAL'
    __bind_key__  = 'XORCISM'

    CredentialID = Column(Integer, primary_key=True)
    AuthenticationTypeID = Column(Integer)
    Username = Column(Text)
    Password = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<CREDENTIAL {self.CredentialID}>'

class CREDENTIALACCESSRECORD(Base):
    __tablename__ = 'CREDENTIALACCESSRECORD'
    __bind_key__  = 'XORCISM'

    CredentialAccessRecordID = Column(Integer, primary_key=True)
    CredentialID = Column(Integer, nullable=False)
    AccessRecordID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationRecordID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CREDENTIALACCESSRECORD {self.CredentialAccessRecordID}>'

class CREDENTIALREPOSITORY(Base):
    __tablename__ = 'CREDENTIALREPOSITORY'
    __bind_key__  = 'XORCISM'

    CredentialRepositoryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CREDENTIALREPOSITORY {self.CredentialRepositoryID}>'

class CRITICALITYLEVEL(Base):
    __tablename__ = 'CRITICALITYLEVEL'
    __bind_key__  = 'XORCISM'

    CriticalityLevelID = Column(Integer, primary_key=True)
    CriticalityLevelGUID = Column(Text)
    CriticalityLevelName = Column(Text)
    CriticalityLevelDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CRITICALITYLEVEL {self.CriticalityLevelID}>'

class CUSTOMOBJECT(Base):
    __tablename__ = 'CUSTOMOBJECT'
    __bind_key__  = 'XORCISM'

    CustomObjectID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CUSTOMOBJECT {self.CustomObjectID}>'

class CWE(Base):
    __tablename__ = 'CWE'
    __bind_key__  = 'XORCISM'

    CWEID = Column(Text, primary_key=True)
    CWEGUID = Column(Text)
    CWEName = Column(Text)
    CWEStatus = Column(Text)
    CWEAbstraction = Column(Text)
    CWEDescriptionSummary = Column(Text)
    CWEExtendedDescription = Column(Text)
    CWECausalNature = Column(Text)
    CWEBackgroundDetails = Column(Text)
    Maintenance_Notes = Column(Text)
    Relationship_Notes = Column(Text)
    Terminology_Notes = Column(Text)
    White_Box_Definitions = Column(Text)
    Platform_Notes = Column(Text)
    Other_Notes = Column(Text)
    Research_Gaps = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    CWEURL = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ImportanceID = Column(Integer)
    CriticalityLevelID = Column(Integer)

    def __repr__(self):
        return f'<CWE {self.CWEID}>'

class CWEAFFECTEDFUNCTION(Base):
    __tablename__ = 'CWEAFFECTEDFUNCTION'
    __bind_key__  = 'XORCISM'

    CWEAffectedFunctionID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    FunctionID = Column(Integer, nullable=False)
    FunctionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEAFFECTEDFUNCTION {self.CWEAffectedFunctionID}>'

class CWEAFFECTEDRESOURCE(Base):
    __tablename__ = 'CWEAFFECTEDRESOURCE'
    __bind_key__  = 'XORCISM'

    CWEAffectedResourceID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    AffectedResourceID = Column(Integer, nullable=False)
    AffectedResourceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEAFFECTEDRESOURCE {self.CWEAffectedResourceID}>'

class CWEALTERNATETERM(Base):
    __tablename__ = 'CWEALTERNATETERM'
    __bind_key__  = 'XORCISM'

    CWEAlternateTermID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    AlternateTerm = Column(Text, nullable=False)
    AlternateTermDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEALTERNATETERM {self.CWEAlternateTermID}>'

class CWEALTERNATETERMTAG(Base):
    __tablename__ = 'CWEALTERNATETERMTAG'
    __bind_key__  = 'XORCISM'

    CWEAlternateTermTagID = Column(Integer, primary_key=True)
    CWEAlternateTermID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEALTERNATETERMTAG {self.CWEAlternateTermTagID}>'

class CWEARCHITECTURALPARADIGM(Base):
    __tablename__ = 'CWEARCHITECTURALPARADIGM'
    __bind_key__  = 'XORCISM'

    CWEArchitecturalParadigmID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    ArchitecturalParadigmID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEARCHITECTURALPARADIGM {self.CWEArchitecturalParadigmID}>'

class CWEATTACKCONSEQUENCE(Base):
    __tablename__ = 'CWEATTACKCONSEQUENCE'
    __bind_key__  = 'XORCISM'

    CWEAttackConsequenceID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    CWEAttackConsequenceOrder = Column(Integer, nullable=False)
    Consequence_Note = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEATTACKCONSEQUENCE {self.CWEAttackConsequenceID}>'

class CWEATTACKCONSEQUENCESCOPE(Base):
    __tablename__ = 'CWEATTACKCONSEQUENCESCOPE'
    __bind_key__  = 'XORCISM'

    CWEAttackConsequenceScopeID = Column(Integer, primary_key=True)
    CWEAttackConsequenceID = Column(Integer)
    AttackScopeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEATTACKCONSEQUENCESCOPE {self.CWEAttackConsequenceScopeID}>'

class CWEATTACKCONSEQUENCETAG(Base):
    __tablename__ = 'CWEATTACKCONSEQUENCETAG'
    __bind_key__  = 'XORCISM'

    CWEAttackConsequenceTagID = Column(Integer, primary_key=True)
    CWEAttackConsequenceID = Column(Integer)
    TagID = Column(Integer)

    def __repr__(self):
        return f'<CWEATTACKCONSEQUENCETAG {self.CWEAttackConsequenceTagID}>'

class CWEATTACKTECHNICALIMPACT(Base):
    __tablename__ = 'CWEATTACKTECHNICALIMPACT'
    __bind_key__  = 'XORCISM'

    CWEAttackTechnicalImpactID = Column(Integer, primary_key=True)
    CWEAttackConsequenceID = Column(Integer)
    AttackTechnicalImpactID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEATTACKTECHNICALIMPACT {self.CWEAttackTechnicalImpactID}>'

class CWEDEMONSTRATIVEEXAMPLE(Base):
    __tablename__ = 'CWEDEMONSTRATIVEEXAMPLE'
    __bind_key__  = 'XORCISM'

    CWEDemonstrativeExampleID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    DemonstrativeExampleID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEDEMONSTRATIVEEXAMPLE {self.CWEDemonstrativeExampleID}>'

class CWEDESCRIPTION(Base):
    __tablename__ = 'CWEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    CWEDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CWEDESCRIPTION {self.CWEDescriptionID}>'

class CWEDETECTIONMETHOD(Base):
    __tablename__ = 'CWEDETECTIONMETHOD'
    __bind_key__  = 'XORCISM'

    CWEDetectionMethodID = Column(Integer, primary_key=True)
    CWEDetectionMethodGUID = Column(Text)
    CWEID = Column(Text, nullable=False)
    CWEGUID = Column(Text)
    DetectionMethodID = Column(Integer, nullable=False)
    DetectionMethodGUID = Column(Text)
    CWEDetectionMethodDescription = Column(Text)
    CWEDetectionMethodEffectiveness = Column(Text)
    CWEDetectionMethodEffectivenessNotes = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWEDETECTIONMETHOD {self.CWEDetectionMethodID}>'

class CWEEXPLOITATIONFACTOR(Base):
    __tablename__ = 'CWEEXPLOITATIONFACTOR'
    __bind_key__  = 'XORCISM'

    CWEExploitationFactorID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    ExploitationFactorID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWEEXPLOITATIONFACTOR {self.CWEExploitationFactorID}>'

class CWEFOROWASPTOP10(Base):
    __tablename__ = 'CWEFOROWASPTOP10'
    __bind_key__  = 'XORCISM'

    CWEOWASPTOP10ID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    OWASPTOP10ID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    Mapping_Fit = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEFOROWASPTOP10 {self.CWEOWASPTOP10ID}>'

class CWEFUNCTIONALAREA(Base):
    __tablename__ = 'CWEFUNCTIONALAREA'
    __bind_key__  = 'XORCISM'

    CWEFunctionalAreaID = Column(Integer, primary_key=True)
    CWEFunctionalAreaGUID = Column(Text)
    CWEID = Column(Text)
    FunctionalAreaID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEFUNCTIONALAREA {self.CWEFunctionalAreaID}>'

class CWELANGUAGE(Base):
    __tablename__ = 'CWELANGUAGE'
    __bind_key__  = 'XORCISM'

    CWELanguageID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    LanguageID = Column(Integer, nullable=False)
    LanguageGUID = Column(Text)
    Prevalence = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWELANGUAGE {self.CWELanguageID}>'

class CWELANGUAGECLASS(Base):
    __tablename__ = 'CWELANGUAGECLASS'
    __bind_key__  = 'XORCISM'

    CWELanguageClassID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    LanguageClassID = Column(Integer, nullable=False)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CWELANGUAGECLASS {self.CWELanguageClassID}>'

class CWEMODEOFINTRODUCTION(Base):
    __tablename__ = 'CWEMODEOFINTRODUCTION'
    __bind_key__  = 'XORCISM'

    CWEModeOfIntroductionID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    ModeOfIntroductionDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWEMODEOFINTRODUCTION {self.CWEModeOfIntroductionID}>'

class CWEMODEOFINTRODUCTIONTAG(Base):
    __tablename__ = 'CWEMODEOFINTRODUCTIONTAG'
    __bind_key__  = 'XORCISM'

    CWEModeOfIntroductionTagID = Column(Integer, primary_key=True)
    CWEModeOfIntroductionID = Column(Integer)
    TagID = Column(Integer)

    def __repr__(self):
        return f'<CWEMODEOFINTRODUCTIONTAG {self.CWEModeOfIntroductionTagID}>'

class CWEORDINALITY(Base):
    __tablename__ = 'CWEORDINALITY'
    __bind_key__  = 'XORCISM'

    CWEOrdinalityID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    WeaknessOrdinality = Column(Text)
    Ordinality_Description = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWEORDINALITY {self.CWEOrdinalityID}>'

class CWEOS(Base):
    __tablename__ = 'CWEOS'
    __bind_key__  = 'XORCISM'

    CWEOSID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    Operating_System_Name = Column(Text)
    Prevalence = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWEOS {self.CWEOSID}>'

class CWEOSCLASS(Base):
    __tablename__ = 'CWEOSCLASS'
    __bind_key__  = 'XORCISM'

    CWEOSClassID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    OSClassID = Column(Integer)
    Prevalence = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWEOSCLASS {self.CWEOSClassID}>'

class CWEREFERENCE(Base):
    __tablename__ = 'CWEREFERENCE'
    __bind_key__  = 'XORCISM'

    CWEReferenceID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    Reference_Section = Column(Text)
    LocalReferenceID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CWEREFERENCE {self.CWEReferenceID}>'

class CWERELATIONSHIPCATEGORY(Base):
    __tablename__ = 'CWERELATIONSHIPCATEGORY'
    __bind_key__  = 'XORCISM'

    CWERelationshipCategoryID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    RelationshipNature = Column(Text, nullable=False)
    RelationshipTargetCWEID = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWERELATIONSHIPCATEGORY {self.CWERelationshipCategoryID}>'

class CWERELEVANTPROPERTY(Base):
    __tablename__ = 'CWERELEVANTPROPERTY'
    __bind_key__  = 'XORCISM'

    CWERelevantPropertyID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    Relevant_Property = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<CWERELEVANTPROPERTY {self.CWERelevantPropertyID}>'

class CWEREPOSITORY(Base):
    __tablename__ = 'CWEREPOSITORY'
    __bind_key__  = 'XORCISM'

    CWERepositoryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<CWEREPOSITORY {self.CWERepositoryID}>'

class CWERESEARCHGAP(Base):
    __tablename__ = 'CWERESEARCHGAP'
    __bind_key__  = 'XORCISM'

    CWEResearchGapID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    ResearchGapText = Column(Text)
    ResearchGapTextClean = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWERESEARCHGAP {self.CWEResearchGapID}>'

class CWETAG(Base):
    __tablename__ = 'CWETAG'
    __bind_key__  = 'XORCISM'

    CWETagID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWETAG {self.CWETagID}>'

class CWETAXONOMYNODE(Base):
    __tablename__ = 'CWETAXONOMYNODE'
    __bind_key__  = 'XORCISM'

    CWETaxonomyNodeID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    TaxonomyNodeID = Column(Integer, nullable=False)
    Mapping_Fit = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<CWETAXONOMYNODE {self.CWETaxonomyNodeID}>'

class CWETECHNOLOGY(Base):
    __tablename__ = 'CWETECHNOLOGY'
    __bind_key__  = 'XORCISM'

    CWETechnologyID = Column(Integer, primary_key=True)
    CWEID = Column(Text)
    TechnologyID = Column(Integer)
    Prevalence = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWETECHNOLOGY {self.CWETechnologyID}>'

class CWETHEORETICALNOTE(Base):
    __tablename__ = 'CWETHEORETICALNOTE'
    __bind_key__  = 'XORCISM'

    CWETheoreticalNoteID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    TheoreticalNoteID = Column(Integer, nullable=False)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWETHEORETICALNOTE {self.CWETheoreticalNoteID}>'

class CWETIMEOFINTRODUCTION(Base):
    __tablename__ = 'CWETIMEOFINTRODUCTION'
    __bind_key__  = 'XORCISM'

    CWETimeOfIntroductionID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    PhaseID = Column(Integer)
    IntroductoryPhase = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<CWETIMEOFINTRODUCTION {self.CWETimeOfIntroductionID}>'

class CWETOP25(Base):
    __tablename__ = 'CWETOP25'
    __bind_key__  = 'XORCISM'

    CWETOP25ID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    YearTop25 = Column(Integer, nullable=False)
    Rank = Column(Integer, nullable=False)
    Score = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<CWETOP25 {self.CWETOP25ID}>'

class DATACLASSIFICATION(Base):
    __tablename__ = 'DATACLASSIFICATION'
    __bind_key__  = 'XORCISM'

    DataClassificationID = Column(Integer, primary_key=True)
    InformationTypeID = Column(Integer)

    def __repr__(self):
        return f'<DATACLASSIFICATION {self.DataClassificationID}>'

class DATADICTIONARY(Base):
    __tablename__ = 'DATADICTIONARY'
    __bind_key__  = 'XORCISM'

    DataDictionaryID = Column(Integer, primary_key=True)
    DictionaryID = Column(Integer)

    def __repr__(self):
        return f'<DATADICTIONARY {self.DataDictionaryID}>'

class DATAEXFILTRATIONPROPERTIES(Base):
    __tablename__ = 'DATAEXFILTRATIONPROPERTIES'
    __bind_key__  = 'XORCISM'

    DataExfiltrationPropertiesID = Column(Integer, primary_key=True)
    DataExfiltrationPropertiesName = Column(Text)
    DataExfiltrationPropertiesDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DATAEXFILTRATIONPROPERTIES {self.DataExfiltrationPropertiesID}>'

class DATAEXFILTRATIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'DATAEXFILTRATIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    DataExfiltrationStrategicObjectiveID = Column(Integer, primary_key=True)
    DataExfiltrationStrategicObjectiveName = Column(Text)
    DataExfiltrationStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DATAEXFILTRATIONSTRATEGICOBJECTIVE {self.DataExfiltrationStrategicObjectiveID}>'

class DATAEXFILTRATIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'DATAEXFILTRATIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    DataExfiltrationTacticalObjectiveID = Column(Integer, primary_key=True)
    DataExfiltrationTacticalObjectiveName = Column(Text)
    DataExfiltrationTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DATAEXFILTRATIONTACTICALOBJECTIVE {self.DataExfiltrationTacticalObjectiveID}>'

class DATAFEED(Base):
    __tablename__ = 'DATAFEED'
    __bind_key__  = 'XORCISM'

    DataFeedID = Column(Integer, primary_key=True)
    FeedID = Column(Integer)

    def __repr__(self):
        return f'<DATAFEED {self.DataFeedID}>'

class DATAFORMAT(Base):
    __tablename__ = 'DATAFORMAT'
    __bind_key__  = 'XORCISM'

    DataFormatID = Column(Integer, primary_key=True)
    DataFormatName = Column(Text)
    DataFormatDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<DATAFORMAT {self.DataFormatID}>'

class DATAMODEL(Base):
    __tablename__ = 'DATAMODEL'
    __bind_key__  = 'XORCISM'

    DataModelID = Column(Integer, primary_key=True)
    ModelID = Column(Integer)

    def __repr__(self):
        return f'<DATAMODEL {self.DataModelID}>'

class DATASEGMENT(Base):
    __tablename__ = 'DATASEGMENT'
    __bind_key__  = 'XORCISM'

    DataSegmentID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DATASEGMENT {self.DataSegmentID}>'

class DATASIZEUNIT(Base):
    __tablename__ = 'DATASIZEUNIT'
    __bind_key__  = 'XORCISM'

    DataSizeUnitID = Column(Integer, primary_key=True)
    DataSizeName = Column(Text, nullable=False)
    DataSizeDescription = Column(Text)
    lang = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<DATASIZEUNIT {self.DataSizeUnitID}>'

class DATATHEFTPROPERTIES(Base):
    __tablename__ = 'DATATHEFTPROPERTIES'
    __bind_key__  = 'XORCISM'

    DataTheftPropertiesID = Column(Integer, primary_key=True)
    DataTheftPropertiesName = Column(Text)
    DataTheftPropertiesDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<DATATHEFTPROPERTIES {self.DataTheftPropertiesID}>'

class DATATHEFTSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'DATATHEFTSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    DataTheftStrategicObjectiveID = Column(Integer, primary_key=True)
    DataTheftStrategicObjectiveName = Column(Text)
    DataTheftStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DATATHEFTSTRATEGICOBJECTIVE {self.DataTheftStrategicObjectiveID}>'

class DATATHEFTTACTICALOBJECTIVE(Base):
    __tablename__ = 'DATATHEFTTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    DataTheftTacticalObjectiveID = Column(Integer, primary_key=True)
    DataTheftTacticalObjectiveName = Column(Text)
    DataTheftTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DATATHEFTTACTICALOBJECTIVE {self.DataTheftTacticalObjectiveID}>'

class DATATRANSFER(Base):
    __tablename__ = 'DATATRANSFER'
    __bind_key__  = 'XORCISM'

    DataTransferID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DATATRANSFER {self.DataTransferID}>'

class DATATRANSFORMATION(Base):
    __tablename__ = 'DATATRANSFORMATION'
    __bind_key__  = 'XORCISM'

    DataTransformationID = Column(Integer, primary_key=True)
    TransformationID = Column(Integer)

    def __repr__(self):
        return f'<DATATRANSFORMATION {self.DataTransformationID}>'

class DATATYPE(Base):
    __tablename__ = 'DATATYPE'
    __bind_key__  = 'XORCISM'

    DataTypeID = Column(Integer, primary_key=True)
    DataTypeName = Column(Text, nullable=False)
    DataTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DATATYPE {self.DataTypeID}>'

class DATETIMEFORMAT(Base):
    __tablename__ = 'DATETIMEFORMAT'
    __bind_key__  = 'XORCISM'

    DateTimeFormatID = Column(Integer, primary_key=True)
    DateTimeFormatValue = Column(Text, nullable=False)
    DataType = Column(Text, nullable=False)
    DateTimeFormatDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<DATETIMEFORMAT {self.DateTimeFormatID}>'

class DEBUGGINGACTIONNAME(Base):
    __tablename__ = 'DEBUGGINGACTIONNAME'
    __bind_key__  = 'XORCISM'

    DebuggingActionNameID = Column(Integer, primary_key=True)
    DebuggingActionNameName = Column(Text, nullable=False)
    DebuggingActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DEBUGGINGACTIONNAME {self.DebuggingActionNameID}>'

class DEFENSETOOL(Base):
    __tablename__ = 'DEFENSETOOL'
    __bind_key__  = 'XORCISM'

    DefenseToolID = Column(Integer, primary_key=True)
    DefenseToolGUID = Column(Text)
    ToolID = Column(Integer)
    DefenseToolName = Column(Text)
    DefenseToolDescription = Column(Text)
    isEncrypted = Column(Integer)
    ReliabilityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<DEFENSETOOL {self.DefenseToolID}>'

class DEFENSETOOLTYPE(Base):
    __tablename__ = 'DEFENSETOOLTYPE'
    __bind_key__  = 'XORCISM'

    DefenseToolTypeID = Column(Integer, primary_key=True)
    DefenseToolTypeName = Column(Text, nullable=False)
    DefenseToolTypeDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<DEFENSETOOLTYPE {self.DefenseToolTypeID}>'

class DEMONSTRATIVEEXAMPLE(Base):
    __tablename__ = 'DEMONSTRATIVEEXAMPLE'
    __bind_key__  = 'XORCISM'

    DemonstrativeExampleID = Column(Integer, primary_key=True)
    DemonstrativeExampleGUID = Column(Text)
    DemonstrativeExampleVocabularyID = Column(Text)
    DemonstrativeExampleIntroText = Column(Text)
    DemonstrativeExampleBody = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    LanguageID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DEMONSTRATIVEEXAMPLE {self.DemonstrativeExampleID}>'

class DEMONSTRATIVEEXAMPLECODE(Base):
    __tablename__ = 'DEMONSTRATIVEEXAMPLECODE'
    __bind_key__  = 'XORCISM'

    DemonstrativeExampleCodeID = Column(Integer, primary_key=True)
    DemonstrativeExampleID = Column(Integer, nullable=False)
    CodeID = Column(Integer, nullable=False)
    Block_Nature = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<DEMONSTRATIVEEXAMPLECODE {self.DemonstrativeExampleCodeID}>'

class DEMONSTRATIVEEXAMPLEREFERENCE(Base):
    __tablename__ = 'DEMONSTRATIVEEXAMPLEREFERENCE'
    __bind_key__  = 'XORCISM'

    DemonstrativeExampleReferenceID = Column(Integer, primary_key=True)
    DemonstrativeExampleID = Column(Integer)
    ReferenceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DEMONSTRATIVEEXAMPLEREFERENCE {self.DemonstrativeExampleReferenceID}>'

class DEMONSTRATIVEEXAMPLEVULNERABILITY(Base):
    __tablename__ = 'DEMONSTRATIVEEXAMPLEVULNERABILITY'
    __bind_key__  = 'XORCISM'

    DemonstrativeExampleVulnerabilityID = Column(Integer, primary_key=True)
    DemonstrativeExampleID = Column(Integer)
    VulnerabilityID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<DEMONSTRATIVEEXAMPLEVULNERABILITY {self.DemonstrativeExampleVulnerabilityID}>'

class DESCRIPTION(Base):
    __tablename__ = 'DESCRIPTION'
    __bind_key__  = 'XORCISM'

    DescriptionID = Column(Integer, primary_key=True)
    DescriptionGUID = Column(Text)
    DescriptionText = Column(Text)
    LocaleID = Column(Integer)
    VersionID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidentialityLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DESCRIPTION {self.DescriptionID}>'

class DESCRIPTIONCHANGERECORD(Base):
    __tablename__ = 'DESCRIPTIONCHANGERECORD'
    __bind_key__  = 'XORCISM'

    DescriptionChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DESCRIPTIONCHANGERECORD {self.DescriptionChangeRecordID}>'

class DESCRIPTIONREFERENCE(Base):
    __tablename__ = 'DESCRIPTIONREFERENCE'
    __bind_key__  = 'XORCISM'

    DescriptionReferenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DESCRIPTIONREFERENCE {self.DescriptionReferenceID}>'

class DESCRIPTIONTAG(Base):
    __tablename__ = 'DESCRIPTIONTAG'
    __bind_key__  = 'XORCISM'

    DescriptionTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DESCRIPTIONTAG {self.DescriptionTagID}>'

class DESTRUCTIONPROPERTIES(Base):
    __tablename__ = 'DESTRUCTIONPROPERTIES'
    __bind_key__  = 'XORCISM'

    DestructionPropertiesID = Column(Integer, primary_key=True)
    DestructionPropertiesName = Column(Text)
    DestructionPropertiesDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DESTRUCTIONPROPERTIES {self.DestructionPropertiesID}>'

class DESTRUCTIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'DESTRUCTIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    DestructionStrategicObjectiveID = Column(Integer, primary_key=True)
    DestructionStrategicObjectiveName = Column(Text)
    DestructionStrategicObjectiveDestruction = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DESTRUCTIONSTRATEGICOBJECTIVE {self.DestructionStrategicObjectiveID}>'

class DESTRUCTIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'DESTRUCTIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    DestructionTacticalObjectiveID = Column(Integer, primary_key=True)
    DestructionTacticalObjectiveName = Column(Text)
    DestructionTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<DESTRUCTIONTACTICALOBJECTIVE {self.DestructionTacticalObjectiveID}>'

class DETECTABILITY(Base):
    __tablename__ = 'DETECTABILITY'
    __bind_key__  = 'XORCISM'

    DetectabilityID = Column(Integer, primary_key=True)
    DetectabilityName = Column(Text, nullable=False)
    DetectabilityDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DETECTABILITY {self.DetectabilityID}>'

class DETECTIONMETHOD(Base):
    __tablename__ = 'DETECTIONMETHOD'
    __bind_key__  = 'XORCISM'

    DetectionMethodID = Column(Integer, primary_key=True)
    DetectionMethodGUID = Column(Text)
    MethodID = Column(Integer)
    DetectionMethodVocabularyID = Column(Text)
    DetectionMethodName = Column(Text, nullable=False)
    DetectionMethodDescription = Column(Text)
    DetectionMethodEffectiveness = Column(Text)
    DetectionMethodEffectivenessNotes = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DETECTIONMETHOD {self.DetectionMethodID}>'

class DEVICE(Base):
    __tablename__ = 'DEVICE'
    __bind_key__  = 'XORCISM'

    DeviceID = Column(Integer, primary_key=True)
    DeviceGUID = Column(Text)
    Device_Type = Column(Text, nullable=False)
    Manufacturer = Column(Text)
    OrganisationID = Column(Integer)
    Model = Column(Text)
    Firmware_Version = Column(Text)
    CPEID = Column(Integer)
    CPEName = Column(Text)
    Serial_Number = Column(Text)
    Description = Column(Text)
    ClockSpeedFrequency = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DEVICE {self.DeviceID}>'

class DEVICEBLACKLIST(Base):
    __tablename__ = 'DEVICEBLACKLIST'
    __bind_key__  = 'XORCISM'

    DeviceBlacklistID = Column(Integer, primary_key=True)
    DeviceID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)
    AssetID = Column(Integer)
    CreatedDate = Column(Integer)
    ValidFromDate = Column(Integer)
    ValidUntilDate = Column(Integer)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<DEVICEBLACKLIST {self.DeviceBlacklistID}>'

class DEVICECOMPONENT(Base):
    __tablename__ = 'DEVICECOMPONENT'
    __bind_key__  = 'XORCISM'

    DeviceComponentID = Column(Integer, primary_key=True)
    DeviceComponentGUID = Column(Text)

    def __repr__(self):
        return f'<DEVICECOMPONENT {self.DeviceComponentID}>'

class DEVICEDRIVERACTIONNAME(Base):
    __tablename__ = 'DEVICEDRIVERACTIONNAME'
    __bind_key__  = 'XORCISM'

    DeviceDriverActionNameID = Column(Integer, primary_key=True)
    DeviceDriverActionNameName = Column(Text, nullable=False)
    DeviceDriverActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DEVICEDRIVERACTIONNAME {self.DeviceDriverActionNameID}>'

class DEVICETYPE(Base):
    __tablename__ = 'DEVICETYPE'
    __bind_key__  = 'XORCISM'

    DeviceTypeID = Column(Integer, primary_key=True)
    DeviceTypeGUID = Column(Text)
    DeviceTypeName = Column(Text)
    DeviceTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DEVICETYPE {self.DeviceTypeID}>'

class DEVICEWHITELIST(Base):
    __tablename__ = 'DEVICEWHITELIST'
    __bind_key__  = 'XORCISM'

    DeviceWhitelistID = Column(Integer, primary_key=True)
    DeviceID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)
    AssetID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<DEVICEWHITELIST {self.DeviceWhitelistID}>'

class DICTIONARY(Base):
    __tablename__ = 'DICTIONARY'
    __bind_key__  = 'XORCISM'

    DictionaryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DICTIONARY {self.DictionaryID}>'

class DIGITALSIGNATUREINFO(Base):
    __tablename__ = 'DIGITALSIGNATUREINFO'
    __bind_key__  = 'XORCISM'

    DigitalSignatureInfoID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DIGITALSIGNATUREINFO {self.DigitalSignatureInfoID}>'

class DIGITALSIGNATURES(Base):
    __tablename__ = 'DIGITALSIGNATURES'
    __bind_key__  = 'XORCISM'

    DigitalSignaturesID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DIGITALSIGNATURES {self.DigitalSignaturesID}>'

class DIRECTORY(Base):
    __tablename__ = 'DIRECTORY'
    __bind_key__  = 'XORCISM'

    DirectoryID = Column(Integer, primary_key=True)
    DirectoryGUID = Column(Text)
    DirectoryPathname = Column(Text)
    DirectoryDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DIRECTORY {self.DirectoryID}>'

class DIRECTORYACTIONNAME(Base):
    __tablename__ = 'DIRECTORYACTIONNAME'
    __bind_key__  = 'XORCISM'

    DirectoryActionNameID = Column(Integer, primary_key=True)
    DirectoryActionNameName = Column(Text, nullable=False)
    DirectoryActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DIRECTORYACTIONNAME {self.DirectoryActionNameID}>'

class DIRECTORYLIST(Base):
    __tablename__ = 'DIRECTORYLIST'
    __bind_key__  = 'XORCISM'

    DirectoryListID = Column(Integer, primary_key=True)
    DirectoryListGUID = Column(Text)

    def __repr__(self):
        return f'<DIRECTORYLIST {self.DirectoryListID}>'

class DISCOVERYMETHOD(Base):
    __tablename__ = 'DISCOVERYMETHOD'
    __bind_key__  = 'XORCISM'

    DiscoveryMethodID = Column(Integer, primary_key=True)
    DiscoveryMethodGUID = Column(Text)
    DiscoveryMethodName = Column(Text)
    MeasureSourceID = Column(Integer)
    DiscoveryMethodDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<DISCOVERYMETHOD {self.DiscoveryMethodID}>'

class DISK(Base):
    __tablename__ = 'DISK'
    __bind_key__  = 'XORCISM'

    DiskID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DISK {self.DiskID}>'

class DISKACTIONNAME(Base):
    __tablename__ = 'DISKACTIONNAME'
    __bind_key__  = 'XORCISM'

    DiskActionNameID = Column(Integer, primary_key=True)
    DiskActionNameName = Column(Text)
    DiskActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DISKACTIONNAME {self.DiskActionNameID}>'

class DISKPARTITION(Base):
    __tablename__ = 'DISKPARTITION'
    __bind_key__  = 'XORCISM'

    DiskPartitionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DISKPARTITION {self.DiskPartitionID}>'

class DNSACTIONNAME(Base):
    __tablename__ = 'DNSACTIONNAME'
    __bind_key__  = 'XORCISM'

    DNSActionNameID = Column(Integer, primary_key=True)
    DNSActionNameName = Column(Text, nullable=False)
    DNSActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DNSACTIONNAME {self.DNSActionNameID}>'

class DNSCACHE(Base):
    __tablename__ = 'DNSCACHE'
    __bind_key__  = 'XORCISM'

    DNSCacheID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DNSCACHE {self.DNSCacheID}>'

class DNSQUERY(Base):
    __tablename__ = 'DNSQUERY'
    __bind_key__  = 'XORCISM'

    DNSQueryID = Column(Integer, primary_key=True)
    DNDQueryGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DNSQUERY {self.DNSQueryID}>'

class DNSRECORD(Base):
    __tablename__ = 'DNSRECORD'
    __bind_key__  = 'XORCISM'

    DNSRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DNSRECORD {self.DNSRecordID}>'

class DOCUMENT(Base):
    __tablename__ = 'DOCUMENT'
    __bind_key__  = 'XORCISM'

    DocumentID = Column(Integer, primary_key=True)
    DocumentGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOCUMENT {self.DocumentID}>'

class DOCUMENTCATEGORY(Base):
    __tablename__ = 'DOCUMENTCATEGORY'
    __bind_key__  = 'XORCISM'

    DocumentCategoryID = Column(Integer, primary_key=True)
    DocumentID = Column(Integer)
    CategoryID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOCUMENTCATEGORY {self.DocumentCategoryID}>'

class DOCUMENTCLASSIFICATION(Base):
    __tablename__ = 'DOCUMENTCLASSIFICATION'
    __bind_key__  = 'XORCISM'

    DocumentClassificationID = Column(Integer, primary_key=True)
    DocumentID = Column(Integer, nullable=False)
    DocumentGUID = Column(Text)
    ClassificationID = Column(Integer, nullable=False)
    ClassificationGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOCUMENTCLASSIFICATION {self.DocumentClassificationID}>'

class DOCUMENTTITLE(Base):
    __tablename__ = 'DOCUMENTTITLE'
    __bind_key__  = 'XORCISM'

    DocumentTitleID = Column(Integer, primary_key=True)
    DocumentID = Column(Integer, nullable=False)
    DocumentGUID = Column(Text)
    TitleID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOCUMENTTITLE {self.DocumentTitleID}>'

class DOCUMENTVERSION(Base):
    __tablename__ = 'DOCUMENTVERSION'
    __bind_key__  = 'XORCISM'

    DocumentVersionID = Column(Integer, primary_key=True)
    DocumentID = Column(Integer, nullable=False)
    DocumentGUID = Column(Text)
    VersionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOCUMENTVERSION {self.DocumentVersionID}>'

class DOCXMLDOCUMENT(Base):
    __tablename__ = 'DOCXMLDOCUMENT'
    __bind_key__  = 'XORCISM'

    DocXMLDocumentID = Column(Integer, primary_key=True)
    DocumentID = Column(Integer)

    def __repr__(self):
        return f'<DOCXMLDOCUMENT {self.DocXMLDocumentID}>'

class DOMAIN(Base):
    __tablename__ = 'DOMAIN'
    __bind_key__  = 'XORCISM'

    DomainID = Column(Integer, primary_key=True)
    DomainGUID = Column(Text)
    DomainName = Column(Text, nullable=False)
    DomainDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DOMAIN {self.DomainID}>'

class DOMAINBLACKLIST(Base):
    __tablename__ = 'DOMAINBLACKLIST'
    __bind_key__  = 'XORCISM'

    DomainBlacklistID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DOMAINBLACKLIST {self.DomainBlacklistID}>'

class DOMAINEMAILADDRESS(Base):
    __tablename__ = 'DOMAINEMAILADDRESS'
    __bind_key__  = 'XORCISM'

    DomainEmailAddressID = Column(Integer, primary_key=True)
    DomainID = Column(Integer, nullable=False)
    EmailAddressID = Column(Integer, nullable=False)
    emailaddress = Column(Text, nullable=False)

    def __repr__(self):
        return f'<DOMAINEMAILADDRESS {self.DomainEmailAddressID}>'

class DOMAINNAME(Base):
    __tablename__ = 'DOMAINNAME'
    __bind_key__  = 'XORCISM'

    DomainNameID = Column(Integer, primary_key=True)
    DomainNameValue = Column(Text)
    DomainNameTypeID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOMAINNAME {self.DomainNameID}>'

class DOMAINNAMEBLACKLIST(Base):
    __tablename__ = 'DOMAINNAMEBLACKLIST'
    __bind_key__  = 'XORCISM'

    DomainNameBlacklistID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DOMAINNAMEBLACKLIST {self.DomainNameBlacklistID}>'

class DOMAINNAMECHANGERECORD(Base):
    __tablename__ = 'DOMAINNAMECHANGERECORD'
    __bind_key__  = 'XORCISM'

    DomainNameChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DOMAINNAMECHANGERECORD {self.DomainNameChangeRecordID}>'

class DOMAINNAMEREPUTATION(Base):
    __tablename__ = 'DOMAINNAMEREPUTATION'
    __bind_key__  = 'XORCISM'

    DomainNameReputationID = Column(Integer, primary_key=True)
    DomainNameID = Column(Integer)
    ReputationID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOMAINNAMEREPUTATION {self.DomainNameReputationID}>'

class DOMAINNAMETYPE(Base):
    __tablename__ = 'DOMAINNAMETYPE'
    __bind_key__  = 'XORCISM'

    DomainNameTypeID = Column(Integer, primary_key=True)
    DomainNameTypeValue = Column(Text)
    DomainNameTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    VocabularyGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOMAINNAMETYPE {self.DomainNameTypeID}>'

class DOMAINORGANISATION(Base):
    __tablename__ = 'DOMAINORGANISATION'
    __bind_key__  = 'XORCISM'

    DomainOrganisationID = Column(Integer, primary_key=True)
    DomainID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer, nullable=False)
    DomainOrganisationDescription = Column(Text)
    RelationshipTypeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<DOMAINORGANISATION {self.DomainOrganisationID}>'

class DOMAINPERSON(Base):
    __tablename__ = 'DOMAINPERSON'
    __bind_key__  = 'XORCISM'

    DomainPersonID = Column(Integer, primary_key=True)
    DomainID = Column(Integer, nullable=False)
    PersonID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<DOMAINPERSON {self.DomainPersonID}>'

class DOMAINTYPE(Base):
    __tablename__ = 'DOMAINTYPE'
    __bind_key__  = 'XORCISM'

    DomainTypeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<DOMAINTYPE {self.DomainTypeID}>'

class DOMAINTYPEENUM(Base):
    __tablename__ = 'DOMAINTYPEENUM'
    __bind_key__  = 'XORCISM'

    DomainTypeEnumID = Column(Integer, primary_key=True)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<DOMAINTYPEENUM {self.DomainTypeEnumID}>'

class DOMAINWHITELIST(Base):
    __tablename__ = 'DOMAINWHITELIST'
    __bind_key__  = 'XORCISM'

    DomainWhitelistID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<DOMAINWHITELIST {self.DomainWhitelistID}>'

class DOWNTIME(Base):
    __tablename__ = 'DOWNTIME'
    __bind_key__  = 'XORCISM'

    DowntimeID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    DownFromDate = Column(Text)
    DownToDate = Column(Text, nullable=False)
    DowntimeDuration = Column(Integer)
    DowntimePlanned = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Text)

    def __repr__(self):
        return f'<DOWNTIME {self.DowntimeID}>'

class DPE(Base):
    __tablename__ = 'DPE'
    __bind_key__  = 'XORCISM'

    DPEID = Column(Integer, primary_key=True)
    CPEID = Column(Text)
    CredentialID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    PortID = Column(Integer)
    ProtocolID = Column(Integer)

    def __repr__(self):
        return f'<DPE {self.DPEID}>'

class EDGE(Base):
    __tablename__ = 'EDGE'
    __bind_key__  = 'XORCISM'

    EdgeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EDGE {self.EdgeID}>'

class EFFECTIVENESS(Base):
    __tablename__ = 'EFFECTIVENESS'
    __bind_key__  = 'XORCISM'

    EffectivenessID = Column(Integer, primary_key=True)
    EffectivenessGUID = Column(Text)
    EffectivenessName = Column(Text, nullable=False)
    EffectivenessDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EFFECTIVENESS {self.EffectivenessID}>'

class EFFECTTYPE(Base):
    __tablename__ = 'EFFECTTYPE'
    __bind_key__  = 'XORCISM'

    EffectTypeID = Column(Integer, primary_key=True)
    EffectTypeName = Column(Text, nullable=False)
    EffectTypeDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<EFFECTTYPE {self.EffectTypeID}>'

class EMAIL(Base):
    __tablename__ = 'EMAIL'
    __bind_key__  = 'XORCISM'

    EmailID = Column(Integer, primary_key=True)
    emailaddress = Column(Text, nullable=False)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EMAIL {self.EmailID}>'

class EMAILADDRESS(Base):
    __tablename__ = 'EMAILADDRESS'
    __bind_key__  = 'XORCISM'

    EmailAddressID = Column(Integer, primary_key=True)
    EmailAddressGUID = Column(Text)
    EmailID = Column(Integer)
    emailaddress = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)

    def __repr__(self):
        return f'<EMAILADDRESS {self.EmailAddressID}>'

class EMAILFORORGANISATION(Base):
    __tablename__ = 'EMAILFORORGANISATION'
    __bind_key__  = 'XORCISM'

    emailaddress = Column(Text, primary_key=True)
    OrganisationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<EMAILFORORGANISATION {self.OrganisationID}>'

class EMAILFORPERSON(Base):
    __tablename__ = 'EMAILFORPERSON'
    __bind_key__  = 'XORCISM'

    emailaddress = Column(Text, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EMAILFORPERSON {self.PersonID}>'

class EMAILHEADER(Base):
    __tablename__ = 'EMAILHEADER'
    __bind_key__  = 'XORCISM'

    EmailHeaderID = Column(Integer, primary_key=True)
    EmailHeaderGUID = Column(Text)
    HeaderID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    Received_Lines = Column(Integer)
    EmailTo = Column(Integer)
    EmailCC = Column(Integer)
    EmailBCC = Column(Integer)
    EmailFrom = Column(Integer)
    EmailSubject = Column(Text)
    In_Reply_To = Column(Text)
    DateSent = Column(Text)
    Message_ID = Column(Text)
    Sender = Column(Integer)
    Reply_To = Column(Integer)
    Errors_To = Column(Text)
    Boundary = Column(Text)
    Content_Type = Column(Text)
    MIMEID = Column(Integer)
    MIME_Version = Column(Text)
    Precedence = Column(Text)
    User_Agent = Column(Text)
    UserAgentID = Column(Integer)
    UserAgentGUID = Column(Text)
    X_Mailer = Column(Text)
    X_Originating_IP = Column(Integer)
    X_Priority = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)

    def __repr__(self):
        return f'<EMAILHEADER {self.EmailHeaderID}>'

class EMAILHEADERTAG(Base):
    __tablename__ = 'EMAILHEADERTAG'
    __bind_key__  = 'XORCISM'

    EmailHeaderTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EMAILHEADERTAG {self.EmailHeaderTagID}>'

class EMAILMESSAGE(Base):
    __tablename__ = 'EMAILMESSAGE'
    __bind_key__  = 'XORCISM'

    EmailMessageID = Column(Integer, primary_key=True)
    EmailMessageGUID = Column(Text)
    MessageID = Column(Integer)
    EmailMessageIsEncrypted = Column(Integer)
    isEncrypted = Column(Integer)
    Email_Server = Column(Text)
    CPEID = Column(Text)
    AssetEmailServerID = Column(Integer)
    AssetEmailServerGUID = Column(Text)
    AssetSourceID = Column(Integer)
    AssetSourceGUID = Column(Text)
    AssetDestinationID = Column(Integer)
    AssetDestinationGUID = Column(Text)
    Raw_Body = Column(Text)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)
    ImportanceID = Column(Integer)
    Raw_Header = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    CollectionMethodID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<EMAILMESSAGE {self.EmailMessageID}>'

class EMAILMESSAGEATTACHMENT(Base):
    __tablename__ = 'EMAILMESSAGEATTACHMENT'
    __bind_key__  = 'XORCISM'

    EmailMessageAttachmentID = Column(Integer, primary_key=True)
    EmailMessageID = Column(Integer, nullable=False)
    EmailMessageGUID = Column(Text)
    AttachmentID = Column(Integer, nullable=False)
    AttachmentGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EMAILMESSAGEATTACHMENT {self.EmailMessageAttachmentID}>'

class EMAILMESSAGECLASSIFICATION(Base):
    __tablename__ = 'EMAILMESSAGECLASSIFICATION'
    __bind_key__  = 'XORCISM'

    EmailMessageClassificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EMAILMESSAGECLASSIFICATION {self.EmailMessageClassificationID}>'

class EMAILMESSAGELINK(Base):
    __tablename__ = 'EMAILMESSAGELINK'
    __bind_key__  = 'XORCISM'

    EmailMessageLinkID = Column(Integer, primary_key=True)
    EmailMessageID = Column(Integer, nullable=False)
    LinkID = Column(Integer, nullable=False)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CollectionMethodID = Column(Integer)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EMAILMESSAGELINK {self.EmailMessageLinkID}>'

class EMAILMESSAGERESTRICTION(Base):
    __tablename__ = 'EMAILMESSAGERESTRICTION'
    __bind_key__  = 'XORCISM'

    EmailMessageRestrictionID = Column(Integer, primary_key=True)
    EmailMessageID = Column(Integer, nullable=False)
    RestrictionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EMAILMESSAGERESTRICTION {self.EmailMessageRestrictionID}>'

class EMAILMESSAGETAG(Base):
    __tablename__ = 'EMAILMESSAGETAG'
    __bind_key__  = 'XORCISM'

    EmailMessageTagID = Column(Integer, primary_key=True)
    EmailMessageID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EMAILMESSAGETAG {self.EmailMessageTagID}>'

class EMAILRECEIVEDLINELIST(Base):
    __tablename__ = 'EMAILRECEIVEDLINELIST'
    __bind_key__  = 'XORCISM'

    EmailReceivedLineListID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EMAILRECEIVEDLINELIST {self.EmailReceivedLineListID}>'

class EMAILRECIPIENT(Base):
    __tablename__ = 'EMAILRECIPIENT'
    __bind_key__  = 'XORCISM'

    EmailRecipientID = Column(Integer, primary_key=True)
    EmailAddressID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EMAILRECIPIENT {self.EmailRecipientID}>'

class EMAILRECIPIENTS(Base):
    __tablename__ = 'EMAILRECIPIENTS'
    __bind_key__  = 'XORCISM'

    EmailRecipientsID = Column(Integer, primary_key=True)
    EmailRecipientsGUID = Column(Text)
    GroupID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EMAILRECIPIENTS {self.EmailRecipientsID}>'

class EMAILRECIPIENTSLIST(Base):
    __tablename__ = 'EMAILRECIPIENTSLIST'
    __bind_key__  = 'XORCISM'

    EmailRecipientsListID = Column(Integer, primary_key=True)
    EmailRecipientsID = Column(Integer, nullable=False)
    EmailRecipientsGUID = Column(Text)
    EmailRecipientID = Column(Integer, nullable=False)
    EmailRecipientGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EMAILRECIPIENTSLIST {self.EmailRecipientsListID}>'

class ENCODING(Base):
    __tablename__ = 'ENCODING'
    __bind_key__  = 'XORCISM'

    EncodingID = Column(Integer, primary_key=True)
    algorithm = Column(Text, nullable=False)
    EncodingAlgorithmID = Column(Integer)
    EncodingDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ENCODING {self.EncodingID}>'

class ENCODINGALGORITHM(Base):
    __tablename__ = 'ENCODINGALGORITHM'
    __bind_key__  = 'XORCISM'

    EncodingAlgorithmID = Column(Integer, primary_key=True)
    AlgorithmID = Column(Integer)

    def __repr__(self):
        return f'<ENCODINGALGORITHM {self.EncodingAlgorithmID}>'

class ENCRYPTION(Base):
    __tablename__ = 'ENCRYPTION'
    __bind_key__  = 'XORCISM'

    EncryptionID = Column(Integer, primary_key=True)
    encryption_mechanism = Column(Text, nullable=False)
    EncryptionMechanismID = Column(Integer)
    encryption_mechanism_ref = Column(Text)
    EncryptionDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<ENCRYPTION {self.EncryptionID}>'

class ENCRYPTIONKEY(Base):
    __tablename__ = 'ENCRYPTIONKEY'
    __bind_key__  = 'XORCISM'

    EncryptionKeyID = Column(Integer, primary_key=True)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ENCRYPTIONKEY {self.EncryptionKeyID}>'

class ENCRYPTIONMECHANISM(Base):
    __tablename__ = 'ENCRYPTIONMECHANISM'
    __bind_key__  = 'XORCISM'

    EncryptionMechanismID = Column(Integer, primary_key=True)
    MechanismID = Column(Integer)
    EncryptionMechanismName = Column(Text)
    EncryptionMechanismDescription = Column(Text)
    TrustLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ENCRYPTIONMECHANISM {self.EncryptionMechanismID}>'

class ENCRYPTIONREFERENCE(Base):
    __tablename__ = 'ENCRYPTIONREFERENCE'
    __bind_key__  = 'XORCISM'

    EncryptionReferenceID = Column(Integer, primary_key=True)
    EncryptionID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<ENCRYPTIONREFERENCE {self.EncryptionReferenceID}>'

class ENDFUNCTION(Base):
    __tablename__ = 'ENDFUNCTION'
    __bind_key__  = 'XORCISM'

    EndFunctionID = Column(Integer, primary_key=True)
    EndsWithCharacters = Column(Text, nullable=False)
    OVALComponentGroupID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ENDFUNCTION {self.EndFunctionID}>'

class ENDIANNESSTYPE(Base):
    __tablename__ = 'ENDIANNESSTYPE'
    __bind_key__  = 'XORCISM'

    EndiannessTypeID = Column(Integer, primary_key=True)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ENDIANNESSTYPE {self.EndiannessTypeID}>'

class ENDPOINT(Base):
    __tablename__ = 'ENDPOINT'
    __bind_key__  = 'XORCISM'

    EndPointID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    DeviceID = Column(Integer)
    AddressID = Column(Integer)
    ProtocolID = Column(Integer)
    ProtocolName = Column(Text)
    PortID = Column(Integer)
    PortNumber = Column(Integer)
    Service = Column(Text)
    Version = Column(Text)
    CPEName = Column(Text)
    SessionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ENDPOINT {self.EndPointID}>'

class ENGINE(Base):
    __tablename__ = 'ENGINE'
    __bind_key__  = 'XORCISM'

    EngineID = Column(Integer, primary_key=True)
    EngineName = Column(Text)
    EngineDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ENGINE {self.EngineID}>'

class ENTITY(Base):
    __tablename__ = 'ENTITY'
    __bind_key__  = 'XORCISM'

    EntityID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ENTITY {self.EntityID}>'

class ENTITYDESCRIPTION(Base):
    __tablename__ = 'ENTITYDESCRIPTION'
    __bind_key__  = 'XORCISM'

    EntityDescriptionID = Column(Integer, primary_key=True)
    EntityID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ENTITYDESCRIPTION {self.EntityDescriptionID}>'

class ENTITYNAME(Base):
    __tablename__ = 'ENTITYNAME'
    __bind_key__  = 'XORCISM'

    EntityNameID = Column(Integer, primary_key=True)
    EntityID = Column(Integer, nullable=False)
    NameID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ENTITYNAME {self.EntityNameID}>'

class ENTITYRESTRICTION(Base):
    __tablename__ = 'ENTITYRESTRICTION'
    __bind_key__  = 'XORCISM'

    EntityRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ENTITYRESTRICTION {self.EntityRestrictionID}>'

class ENTITYTYPE(Base):
    __tablename__ = 'ENTITYTYPE'
    __bind_key__  = 'XORCISM'

    EntityTypeID = Column(Integer, primary_key=True)
    EntityID = Column(Integer, nullable=False)
    TypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ENTITYTYPE {self.EntityTypeID}>'

class ENTRYPOINT(Base):
    __tablename__ = 'ENTRYPOINT'
    __bind_key__  = 'XORCISM'

    EntryPointID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ENTRYPOINT {self.EntryPointID}>'

class ENTRYVARIABLE(Base):
    __tablename__ = 'ENTRYVARIABLE'
    __bind_key__  = 'XORCISM'

    EntryVariableID = Column(Integer, primary_key=True)
    VariableID = Column(Integer)

    def __repr__(self):
        return f'<ENTRYVARIABLE {self.EntryVariableID}>'

class ENUMERATIONVERSION(Base):
    __tablename__ = 'ENUMERATIONVERSION'
    __bind_key__  = 'XORCISM'

    EnumerationVersionID = Column(Integer, primary_key=True)
    EnumerationName = Column(Text)
    VersionID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ENUMERATIONVERSION {self.EnumerationVersionID}>'

class ENVIRONMENT(Base):
    __tablename__ = 'ENVIRONMENT'
    __bind_key__  = 'XORCISM'

    EnvironmentID = Column(Integer, primary_key=True)
    CapecEnvironmentID = Column(Text)
    EnvironmentTitle = Column(Text, nullable=False)
    EnvironmentDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ENVIRONMENT {self.EnvironmentID}>'

class ESCAPEREGEXFUNCTION(Base):
    __tablename__ = 'ESCAPEREGEXFUNCTION'
    __bind_key__  = 'XORCISM'

    EscapeRegexFunctionID = Column(Integer, primary_key=True)
    OVALComponentGroupID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ESCAPEREGEXFUNCTION {self.EscapeRegexFunctionID}>'

class EVALUATIONMETHOD(Base):
    __tablename__ = 'EVALUATIONMETHOD'
    __bind_key__  = 'XORCISM'

    EvaluationMethodID = Column(Integer, primary_key=True)
    MethodID = Column(Integer)
    VocabularyID = Column(Integer)
    ReliabilityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EVALUATIONMETHOD {self.EvaluationMethodID}>'

class EVENT(Base):
    __tablename__ = 'EVENT'
    __bind_key__  = 'XORCISM'

    EventID = Column(Integer, primary_key=True)
    EventGUID = Column(Text)
    EventName = Column(Text)
    EventTypeID = Column(Integer)
    start_datetime = Column(Text)
    stop_datetime = Column(Text)
    AnomalyEvent = Column(Integer)
    AnomalyDescription = Column(Text)
    AuditRecordEvent = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EVENT {self.EventID}>'

class EVENTCOLLECTIONMETHOD(Base):
    __tablename__ = 'EVENTCOLLECTIONMETHOD'
    __bind_key__  = 'XORCISM'

    EventCollectionMethodID = Column(Integer, primary_key=True)
    EventID = Column(Integer, nullable=False)
    EventGUID = Column(Text)
    CollectionMethodID = Column(Integer, nullable=False)
    CollectionMethodGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    AssetID = Column(Integer)
    DeviceID = Column(Integer)
    ProductID = Column(Integer)
    CPEID = Column(Integer)
    CPEName = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EVENTCOLLECTIONMETHOD {self.EventCollectionMethodID}>'

class EVENTCOMMENT(Base):
    __tablename__ = 'EVENTCOMMENT'
    __bind_key__  = 'XORCISM'

    EventCommentID = Column(Integer, primary_key=True)
    Comment = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<EVENTCOMMENT {self.EventCommentID}>'

class EVENTCOMMENTFOREVENT(Base):
    __tablename__ = 'EVENTCOMMENTFOREVENT'
    __bind_key__  = 'XORCISM'

    EventEventCommentID = Column(Integer, primary_key=True)
    EventID = Column(Integer, nullable=False)
    EventCommentID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EVENTCOMMENTFOREVENT {self.EventEventCommentID}>'

class EVENTENDPOINT(Base):
    __tablename__ = 'EVENTENDPOINT'
    __bind_key__  = 'XORCISM'

    EndPointEventID = Column(Integer, primary_key=True)
    EventID = Column(Integer, nullable=False)
    EndPointID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EVENTENDPOINT {self.EndPointEventID}>'

class EVENTFILTER(Base):
    __tablename__ = 'EVENTFILTER'
    __bind_key__  = 'XORCISM'

    EventFilterID = Column(Integer, primary_key=True)
    EventFilterContent = Column(Text)
    EventFilterDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EVENTFILTER {self.EventFilterID}>'

class EVENTFORASSET(Base):
    __tablename__ = 'EVENTFORASSET'
    __bind_key__  = 'XORCISM'

    AssetEventID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    relationshiptype = Column(Text)
    relationshipscope = Column(Text)
    EventID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<EVENTFORASSET {self.AssetEventID}>'

class EVENTFOREVENT(Base):
    __tablename__ = 'EVENTFOREVENT'
    __bind_key__  = 'XORCISM'

    EventForEventID = Column(Integer, primary_key=True)
    EventRefID = Column(Integer, nullable=False)
    relationshiptype = Column(Text)
    relationshipscope = Column(Text)
    EventSubjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EVENTFOREVENT {self.EventForEventID}>'

class EVENTFORINCIDENT(Base):
    __tablename__ = 'EVENTFORINCIDENT'
    __bind_key__  = 'XORCISM'

    IncidentEventID = Column(Integer, primary_key=True)
    EventID = Column(Integer, nullable=False)
    IncidentID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EVENTFORINCIDENT {self.IncidentEventID}>'

class EVENTPROPERTY(Base):
    __tablename__ = 'EVENTPROPERTY'
    __bind_key__  = 'XORCISM'

    EventPropertyID = Column(Integer, primary_key=True)
    EventPropertyGUID = Column(Text)
    EventPropertyIDREF = Column(Text)
    EventPropertyName = Column(Text)
    EventPropertyDescription = Column(Text)
    appears_random = Column(Integer)
    datatype = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<EVENTPROPERTY {self.EventPropertyID}>'

class EVENTPROPERTYADDRESS(Base):
    __tablename__ = 'EVENTPROPERTYADDRESS'
    __bind_key__  = 'XORCISM'

    EventPropertyAddressID = Column(Integer, primary_key=True)
    EventPropertyID = Column(Integer, nullable=False)
    AddressID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<EVENTPROPERTYADDRESS {self.EventPropertyAddressID}>'

class EVENTPROPERTYFOREVENT(Base):
    __tablename__ = 'EVENTPROPERTYFOREVENT'
    __bind_key__  = 'XORCISM'

    EventEventPropertyID = Column(Integer, primary_key=True)
    EventID = Column(Integer, nullable=False)
    EventPropertyID = Column(Integer, nullable=False)
    EventPropertyValue = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EVENTPROPERTYFOREVENT {self.EventEventPropertyID}>'

class EVENTSIGNATURE(Base):
    __tablename__ = 'EVENTSIGNATURE'
    __bind_key__  = 'XORCISM'

    EventSignatureID = Column(Integer, primary_key=True)
    EventSignatureGUID = Column(Text)
    EventID = Column(Integer, nullable=False)
    EventGUID = Column(Text)
    SignatureID = Column(Integer, nullable=False)
    SignatureGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    total_packets_collected = Column(Integer)
    total_bytes_collected = Column(Integer)
    data_flow_direction = Column(Text)
    connection_start_datetime = Column(Text)
    connection_end_datetime = Column(Text)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EVENTSIGNATURE {self.EventSignatureID}>'

class EVENTSUPPRESSION(Base):
    __tablename__ = 'EVENTSUPPRESSION'
    __bind_key__  = 'XORCISM'

    EventSuppressionID = Column(Integer, primary_key=True)
    EventSuppressionContent = Column(Text)
    EventSuppressionDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EVENTSUPPRESSION {self.EventSuppressionID}>'

class EVENTTYPE(Base):
    __tablename__ = 'EVENTTYPE'
    __bind_key__  = 'XORCISM'

    EventTypeID = Column(Integer, primary_key=True)
    EventTypeName = Column(Text, nullable=False)
    EventTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EVENTTYPE {self.EventTypeID}>'

class EVIDENCE(Base):
    __tablename__ = 'EVIDENCE'
    __bind_key__  = 'XORCISM'

    EvidenceID = Column(Integer, primary_key=True)
    EvidenceGUID = Column(Text)
    EvidenceName = Column(Text)
    EvidenceDescription = Column(Text)
    isEncrypted = Column(Integer)
    ConfidentialityLevelID = Column(Integer)
    ImportanceID = Column(Integer)
    SourceID = Column(Integer)
    CollectionMethodID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ReliabilityID = Column(Integer)

    def __repr__(self):
        return f'<EVIDENCE {self.EvidenceID}>'

class EVIDENCEACCESSRECORD(Base):
    __tablename__ = 'EVIDENCEACCESSRECORD'
    __bind_key__  = 'XORCISM'

    EvidenceAccessRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EVIDENCEACCESSRECORD {self.EvidenceAccessRecordID}>'

class EVIDENCEACL(Base):
    __tablename__ = 'EVIDENCEACL'
    __bind_key__  = 'XORCISM'

    EvidenceACLID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EVIDENCEACL {self.EvidenceACLID}>'

class EVIDENCECATEGORY(Base):
    __tablename__ = 'EVIDENCECATEGORY'
    __bind_key__  = 'XORCISM'

    EvidenceCategoryID = Column(Integer, primary_key=True)
    EvidenceCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    EvidenceCategoryName = Column(Text)
    EvidenceCategoryDescription = Column(Text)
    isEncrypted = Column(Integer)
    ReliabilityID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<EVIDENCECATEGORY {self.EvidenceCategoryID}>'

class EVIDENCERESTRICTION(Base):
    __tablename__ = 'EVIDENCERESTRICTION'
    __bind_key__  = 'XORCISM'

    EvidenceRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EVIDENCERESTRICTION {self.EvidenceRestrictionID}>'

class EXCELFILE(Base):
    __tablename__ = 'EXCELFILE'
    __bind_key__  = 'XORCISM'

    ExcelFileID = Column(Integer, primary_key=True)
    FileID = Column(Integer)

    def __repr__(self):
        return f'<EXCELFILE {self.ExcelFileID}>'

class EXIFTAG(Base):
    __tablename__ = 'EXIFTAG'
    __bind_key__  = 'XORCISM'

    EXIFTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EXIFTAG {self.EXIFTagID}>'

class EXISTENCEENUMERATION(Base):
    __tablename__ = 'EXISTENCEENUMERATION'
    __bind_key__  = 'XORCISM'

    ExistenceEnumerationID = Column(Integer, primary_key=True)
    ExistenceValue = Column(Text, nullable=False)
    ExistenceDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EXISTENCEENUMERATION {self.ExistenceEnumerationID}>'

class EXPLOIT(Base):
    __tablename__ = 'EXPLOIT'
    __bind_key__  = 'XORCISM'

    ExploitID = Column(Integer, primary_key=True)
    ExploitGUID = Column(Text)
    ExploitReferential = Column(Text)
    ExploitRefID = Column(Text)
    SourceID = Column(Integer)
    SourceGUID = Column(Text)
    ExploitName = Column(Text)
    ExploitLocation = Column(Text)
    TEXT = Column(Text)
    Verification = Column(Integer)
    Platform = Column(Text)
    Author = Column(Text)
    AuthorID = Column(Integer)
    PersonID = Column(Integer)
    RPORT = Column(Integer)
    ExploitDescription = Column(Text)
    ExploitType = Column(Text)
    CodeID = Column(Integer)
    ExploitCode = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ReliabilityID = Column(Integer)
    isEncrypted = Column(Integer)
    LastCheckDate = Column(Text)

    def __repr__(self):
        return f'<EXPLOIT {self.ExploitID}>'

class EXPLOITABILITY(Base):
    __tablename__ = 'EXPLOITABILITY'
    __bind_key__  = 'XORCISM'

    ExploitabilityID = Column(Integer, primary_key=True)
    ExploitabilityLevel = Column(Text, nullable=False)
    ExploitabilityDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EXPLOITABILITY {self.ExploitabilityID}>'

class EXPLOITACCESSRECORD(Base):
    __tablename__ = 'EXPLOITACCESSRECORD'
    __bind_key__  = 'XORCISM'

    ExploitAccessRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EXPLOITACCESSRECORD {self.ExploitAccessRecordID}>'

class EXPLOITATIONFACTOR(Base):
    __tablename__ = 'EXPLOITATIONFACTOR'
    __bind_key__  = 'XORCISM'

    ExploitationFactorID = Column(Integer, primary_key=True)
    ExploitationFactorGUID = Column(Text)
    ExploitationFactorName = Column(Text)
    ExploitationFactorDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<EXPLOITATIONFACTOR {self.ExploitationFactorID}>'

class EXPLOITAUTHOR(Base):
    __tablename__ = 'EXPLOITAUTHOR'
    __bind_key__  = 'XORCISM'

    ExploitAuthorID = Column(Integer, primary_key=True)
    ExploitID = Column(Integer, nullable=False)
    ExploitGUID = Column(Text)
    AuthorID = Column(Integer, nullable=False)
    AuthorGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITAUTHOR {self.ExploitAuthorID}>'

class EXPLOITCATEGORY(Base):
    __tablename__ = 'EXPLOITCATEGORY'
    __bind_key__  = 'XORCISM'

    ExploitCategoryID = Column(Integer, primary_key=True)
    CategoryID = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITCATEGORY {self.ExploitCategoryID}>'

class EXPLOITCHANGERECORD(Base):
    __tablename__ = 'EXPLOITCHANGERECORD'
    __bind_key__  = 'XORCISM'

    ExploitChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EXPLOITCHANGERECORD {self.ExploitChangeRecordID}>'

class EXPLOITDESCRIPTION(Base):
    __tablename__ = 'EXPLOITDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ExploitDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EXPLOITDESCRIPTION {self.ExploitDescriptionID}>'

class EXPLOITFILE(Base):
    __tablename__ = 'EXPLOITFILE'
    __bind_key__  = 'XORCISM'

    ExploitFileID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EXPLOITFILE {self.ExploitFileID}>'

class EXPLOITFORCPE(Base):
    __tablename__ = 'EXPLOITFORCPE'
    __bind_key__  = 'XORCISM'

    CPEExploitID = Column(Integer, primary_key=True)
    CPEExploitGUID = Column(Text)
    CPEID = Column(Integer)
    CPEName = Column(Text)
    ExploitID = Column(Integer, nullable=False)
    ExploitGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ExploitCPEName = Column(Text)
    ExploitCPEDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITFORCPE {self.CPEExploitID}>'

class EXPLOITFORFUNCTION(Base):
    __tablename__ = 'EXPLOITFORFUNCTION'
    __bind_key__  = 'XORCISM'

    ExploitFunctionID = Column(Integer, primary_key=True)
    ExploitFunctionGUID = Column(Text)
    ExploitID = Column(Integer, nullable=False)
    ExploitGUID = Column(Text)
    ExploitFunctionRelationship = Column(Text)
    FunctionID = Column(Integer, nullable=False)
    FunctionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITFORFUNCTION {self.ExploitFunctionID}>'

class EXPLOITFORREFERENCE(Base):
    __tablename__ = 'EXPLOITFORREFERENCE'
    __bind_key__  = 'XORCISM'

    ExploitReferenceID = Column(Integer, primary_key=True)
    ExploitReferenceGUID = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    ExploitID = Column(Integer, nullable=False)
    ExploitGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITFORREFERENCE {self.ExploitReferenceID}>'

class EXPLOITFORTECHNOLOGY(Base):
    __tablename__ = 'EXPLOITFORTECHNOLOGY'
    __bind_key__  = 'XORCISM'

    ExploitTechnologyID = Column(Integer, primary_key=True)
    TechnologyID = Column(Integer)
    ExploitID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITFORTECHNOLOGY {self.ExploitTechnologyID}>'

class EXPLOITFORTHREATACTORTTP(Base):
    __tablename__ = 'EXPLOITFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    ThreatActorTTPExploitID = Column(Integer, primary_key=True)
    ExploitID = Column(Integer, nullable=False)
    ThreatActorTTPID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<EXPLOITFORTHREATACTORTTP {self.ThreatActorTTPExploitID}>'

class EXPLOITFORURI(Base):
    __tablename__ = 'EXPLOITFORURI'
    __bind_key__  = 'XORCISM'

    ExploitURIID = Column(Integer, primary_key=True)
    URIObjectID = Column(Integer)
    ExploitID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITFORURI {self.ExploitURIID}>'

class EXPLOITFORVULNERABILITY(Base):
    __tablename__ = 'EXPLOITFORVULNERABILITY'
    __bind_key__  = 'XORCISM'

    VulnerabilityExploitID = Column(Integer, primary_key=True)
    VulnerabilityExploitGUID = Column(Text)
    VulnerabilityExploitDescription = Column(Text)
    ExploitID = Column(Integer, nullable=False)
    ExploitGUID = Column(Text)
    VulnerabilityID = Column(Integer, nullable=False)
    VulnerabilityGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    RepositoryID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITFORVULNERABILITY {self.VulnerabilityExploitID}>'

class EXPLOITLANGUAGE(Base):
    __tablename__ = 'EXPLOITLANGUAGE'
    __bind_key__  = 'XORCISM'

    ExploitLanguageID = Column(Integer, primary_key=True)
    ExploitID = Column(Integer)
    ExploitGUID = Column(Text)
    LanguageID = Column(Integer)
    LanguageGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITLANGUAGE {self.ExploitLanguageID}>'

class EXPLOITLIKELIHOOD(Base):
    __tablename__ = 'EXPLOITLIKELIHOOD'
    __bind_key__  = 'XORCISM'

    ExploitLikelihoodID = Column(Integer, primary_key=True)
    Likelihood = Column(Text, nullable=False)
    LikelihoodDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<EXPLOITLIKELIHOOD {self.ExploitLikelihoodID}>'

class EXPLOITLIKELIHOODFORATTACKPATTERN(Base):
    __tablename__ = 'EXPLOITLIKELIHOODFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternExploitLikelihoodID = Column(Integer, primary_key=True)
    ExploitLikelihoodID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    Explanation = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITLIKELIHOODFORATTACKPATTERN {self.AttackPatternExploitLikelihoodID}>'

class EXPLOITLIKELIHOODFORCWE(Base):
    __tablename__ = 'EXPLOITLIKELIHOODFORCWE'
    __bind_key__  = 'XORCISM'

    ExploitLikelihoodForCWEID = Column(Integer, primary_key=True)
    CWEID = Column(Text, nullable=False)
    ExploitLikelihoodID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    RepositoryID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITLIKELIHOODFORCWE {self.ExploitLikelihoodForCWEID}>'

class EXPLOITOSINSTRUCTIONMEMORYADDRESS(Base):
    __tablename__ = 'EXPLOITOSINSTRUCTIONMEMORYADDRESS'
    __bind_key__  = 'XORCISM'

    ExploitOSInstructionMemoryAddressID = Column(Integer, primary_key=True)
    ExploitID = Column(Integer, nullable=False)
    OSInstructionMemoryAddressID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITOSINSTRUCTIONMEMORYADDRESS {self.ExploitOSInstructionMemoryAddressID}>'

class EXPLOITPARAMETER(Base):
    __tablename__ = 'EXPLOITPARAMETER'
    __bind_key__  = 'XORCISM'

    ExploitParameterID = Column(Integer, primary_key=True)
    ExploitParameterName = Column(Text, nullable=False)
    DefaultValue = Column(Text)
    ExploitParameterDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<EXPLOITPARAMETER {self.ExploitParameterID}>'

class EXPLOITPARAMETERFOREXPLOIT(Base):
    __tablename__ = 'EXPLOITPARAMETERFOREXPLOIT'
    __bind_key__  = 'XORCISM'

    ExploitParametersID = Column(Integer, primary_key=True)
    ExploitID = Column(Integer, nullable=False)
    ExploitParameterID = Column(Integer, nullable=False)
    OrderRank = Column(Integer)
    DefaultValue = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<EXPLOITPARAMETERFOREXPLOIT {self.ExploitParametersID}>'

class EXPLOITPLATFORM(Base):
    __tablename__ = 'EXPLOITPLATFORM'
    __bind_key__  = 'XORCISM'

    ExploitPlatformID = Column(Integer, primary_key=True)
    ExploitID = Column(Integer)
    PlatformID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITPLATFORM {self.ExploitPlatformID}>'

class EXPLOITRESTRICTION(Base):
    __tablename__ = 'EXPLOITRESTRICTION'
    __bind_key__  = 'XORCISM'

    ExploitRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EXPLOITRESTRICTION {self.ExploitRestrictionID}>'

class EXPLOITTAG(Base):
    __tablename__ = 'EXPLOITTAG'
    __bind_key__  = 'XORCISM'

    ExploitTagID = Column(Integer, primary_key=True)
    ExploitID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<EXPLOITTAG {self.ExploitTagID}>'

class EXPOSURELEVEL(Base):
    __tablename__ = 'EXPOSURELEVEL'
    __bind_key__  = 'XORCISM'

    ExposureLevelID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EXPOSURELEVEL {self.ExposureLevelID}>'

class EXTRACTEDFEATURES(Base):
    __tablename__ = 'EXTRACTEDFEATURES'
    __bind_key__  = 'XORCISM'

    ExtractedFeaturesID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<EXTRACTEDFEATURES {self.ExtractedFeaturesID}>'

class FACILITY(Base):
    __tablename__ = 'FACILITY'
    __bind_key__  = 'XORCISM'

    FacilityID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FACILITY {self.FacilityID}>'

class FACILITYPHYSICALLOCATION(Base):
    __tablename__ = 'FACILITYPHYSICALLOCATION'
    __bind_key__  = 'XORCISM'

    FacilityPhysicalLocationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FACILITYPHYSICALLOCATION {self.FacilityPhysicalLocationID}>'

class FACTORY(Base):
    __tablename__ = 'FACTORY'
    __bind_key__  = 'XORCISM'

    FactoryID = Column(Integer, primary_key=True)
    ManufacturID = Column(Integer)

    def __repr__(self):
        return f'<FACTORY {self.FactoryID}>'

class FACTORYASSURANCE(Base):
    __tablename__ = 'FACTORYASSURANCE'
    __bind_key__  = 'XORCISM'

    FactoryAssuranceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FACTORYASSURANCE {self.FactoryAssuranceID}>'

class FACTORYCOMPLIANCE(Base):
    __tablename__ = 'FACTORYCOMPLIANCE'
    __bind_key__  = 'XORCISM'

    FactoryComplianceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FACTORYCOMPLIANCE {self.FactoryComplianceID}>'

class FACTORYPOLICY(Base):
    __tablename__ = 'FACTORYPOLICY'
    __bind_key__  = 'XORCISM'

    FactoryPolicyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FACTORYPOLICY {self.FactoryPolicyID}>'

class FAX(Base):
    __tablename__ = 'FAX'
    __bind_key__  = 'XORCISM'

    FaxID = Column(Integer, primary_key=True)
    TelephoneID = Column(Integer)

    def __repr__(self):
        return f'<FAX {self.FaxID}>'

class FEED(Base):
    __tablename__ = 'FEED'
    __bind_key__  = 'XORCISM'

    FeedID = Column(Integer, primary_key=True)
    RepositoryID = Column(Integer)
    ReferenceID = Column(Integer)

    def __repr__(self):
        return f'<FEED {self.FeedID}>'

class FIELD(Base):
    __tablename__ = 'FIELD'
    __bind_key__  = 'XORCISM'

    FieldID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FIELD {self.FieldID}>'

class FILE(Base):
    __tablename__ = 'FILE'
    __bind_key__  = 'XORCISM'

    FileID = Column(Integer, primary_key=True)
    FileGUID = Column(Text)
    FileName = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FILE {self.FileID}>'

class FILEACTIONNAME(Base):
    __tablename__ = 'FILEACTIONNAME'
    __bind_key__  = 'XORCISM'

    FileActionNameID = Column(Integer, primary_key=True)
    FileActionNameName = Column(Text, nullable=False)
    FileActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<FILEACTIONNAME {self.FileActionNameID}>'

class FILECHANGERECORD(Base):
    __tablename__ = 'FILECHANGERECORD'
    __bind_key__  = 'XORCISM'

    FileChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FILECHANGERECORD {self.FileChangeRecordID}>'

class FILECLASSIFICATION(Base):
    __tablename__ = 'FILECLASSIFICATION'
    __bind_key__  = 'XORCISM'

    FileClassificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FILECLASSIFICATION {self.FileClassificationID}>'

class FILEDESCRIPTION(Base):
    __tablename__ = 'FILEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    FileDescriptionID = Column(Integer, primary_key=True)
    FileID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FILEDESCRIPTION {self.FileDescriptionID}>'

class FILEENCRYPTION(Base):
    __tablename__ = 'FILEENCRYPTION'
    __bind_key__  = 'XORCISM'

    FileEncryptionID = Column(Integer, primary_key=True)
    FileID = Column(Integer, nullable=False)
    EncryptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FILEENCRYPTION {self.FileEncryptionID}>'

class FILEEXTENSION(Base):
    __tablename__ = 'FILEEXTENSION'
    __bind_key__  = 'XORCISM'

    FileExtensionID = Column(Integer, primary_key=True)
    FileExtensionGUID = Column(Text)
    FileExtensionName = Column(Text)
    FileExtensionDescription = Column(Text)
    FileExtensionValue = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FILEEXTENSION {self.FileExtensionID}>'

class FILEEXTENSIONBLACKLIST(Base):
    __tablename__ = 'FILEEXTENSIONBLACKLIST'
    __bind_key__  = 'XORCISM'

    FileExtensionBlacklistID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FILEEXTENSIONBLACKLIST {self.FileExtensionBlacklistID}>'

class FILEEXTENSIONWHITELIST(Base):
    __tablename__ = 'FILEEXTENSIONWHITELIST'
    __bind_key__  = 'XORCISM'

    FileExtensionWhitelistID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FILEEXTENSIONWHITELIST {self.FileExtensionWhitelistID}>'

class FILELIST(Base):
    __tablename__ = 'FILELIST'
    __bind_key__  = 'XORCISM'

    FileListID = Column(Integer, primary_key=True)
    FileListGUID = Column(Text)
    FileListName = Column(Text)
    FileListDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FILELIST {self.FileListID}>'

class FILELISTFILES(Base):
    __tablename__ = 'FILELISTFILES'
    __bind_key__  = 'XORCISM'

    FileListFileID = Column(Integer, primary_key=True)
    FileListID = Column(Integer, nullable=False)
    FileListGUID = Column(Text)
    FileID = Column(Integer, nullable=False)
    FileGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FILELISTFILES {self.FileListFileID}>'

class FILEREFERENCE(Base):
    __tablename__ = 'FILEREFERENCE'
    __bind_key__  = 'XORCISM'

    FileReferenceID = Column(Integer, primary_key=True)
    FileReferenceGUID = Column(Text)
    FileID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FILEREFERENCE {self.FileReferenceID}>'

class FILEREPOSITORY(Base):
    __tablename__ = 'FILEREPOSITORY'
    __bind_key__  = 'XORCISM'

    FileRepositoryID = Column(Integer, primary_key=True)
    FileID = Column(Integer, nullable=False)
    FileGUID = Column(Text)
    RepositoryID = Column(Integer, nullable=False)
    RepositoryGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    LastCheckedDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<FILEREPOSITORY {self.FileRepositoryID}>'

class FILERESTRICTION(Base):
    __tablename__ = 'FILERESTRICTION'
    __bind_key__  = 'XORCISM'

    FileRestrictionID = Column(Integer, primary_key=True)
    FileID = Column(Integer, nullable=False)
    RestrictionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<FILERESTRICTION {self.FileRestrictionID}>'

class FILERESTRICTIONCHANGERECORD(Base):
    __tablename__ = 'FILERESTRICTIONCHANGERECORD'
    __bind_key__  = 'XORCISM'

    FileRestrictionChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FILERESTRICTIONCHANGERECORD {self.FileRestrictionChangeRecordID}>'

class FILETAG(Base):
    __tablename__ = 'FILETAG'
    __bind_key__  = 'XORCISM'

    FileTagID = Column(Integer, primary_key=True)
    FileID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FILETAG {self.FileTagID}>'

class FILEVERSION(Base):
    __tablename__ = 'FILEVERSION'
    __bind_key__  = 'XORCISM'

    FileVersionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FILEVERSION {self.FileVersionID}>'

class FILTER(Base):
    __tablename__ = 'FILTER'
    __bind_key__  = 'XORCISM'

    FilterID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FILTER {self.FilterID}>'

class FILTERACTION(Base):
    __tablename__ = 'FILTERACTION'
    __bind_key__  = 'XORCISM'

    FilterActionID = Column(Integer, primary_key=True)
    FilterActionValue = Column(Text, nullable=False)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FILTERACTION {self.FilterActionID}>'

class FINDING(Base):
    __tablename__ = 'FINDING'
    __bind_key__  = 'XORCISM'

    FindingID = Column(Integer, primary_key=True)
    FindingGUID = Column(Text)
    FindingName = Column(Text)
    FindingDescription = Column(Text)
    ImportanceID = Column(Integer)
    AssetID = Column(Integer)
    EndPointID = Column(Integer)
    ApplicationID = Column(Integer)
    FindingStatus = Column(Text)
    CriticalityLevelID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ReportedDate = Column(Text)
    FindingDecision = Column(Text)
    MitigationDate = Column(Text)
    RemediationDate = Column(Text)
    FindingResult = Column(Text)
    FindingURL = Column(Text)
    VulnerableParameterType = Column(Text)
    VulnerableParameter = Column(Text)
    VulnerableParameterValue = Column(Text)
    FindingRequest = Column(Text)
    RequestType = Column(Text)
    FindingResponse = Column(Text)
    IsFalsePositive = Column(Integer)
    VulnerabilityID = Column(Integer)
    BLOB = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    JobID = Column(Integer)

    def __repr__(self):
        return f'<FINDING {self.FindingID}>'

class FINDINGASSET(Base):
    __tablename__ = 'FINDINGASSET'
    __bind_key__  = 'XORCISM'

    FindingAssetID = Column(Integer, primary_key=True)
    FindingAssetGUID = Column(Text)
    FindingID = Column(Integer)
    FindingGUID = Column(Text)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    FindingAssetRelationship = Column(Text)
    FindingAssetDescription = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FINDINGASSET {self.FindingAssetID}>'

class FINDINGCATEGORY(Base):
    __tablename__ = 'FINDINGCATEGORY'
    __bind_key__  = 'XORCISM'

    FindingCategoryID = Column(Integer, primary_key=True)
    FindingCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    FindingCategoryName = Column(Text)
    FindingCategoryDescription = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ImportanceID = Column(Integer)

    def __repr__(self):
        return f'<FINDINGCATEGORY {self.FindingCategoryID}>'

class FINDINGCATEGORYRACIMATRIX(Base):
    __tablename__ = 'FINDINGCATEGORYRACIMATRIX'
    __bind_key__  = 'XORCISM'

    FindingCategoryRACIMatrixID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FINDINGCATEGORYRACIMATRIX {self.FindingCategoryRACIMatrixID}>'

class FINDINGCHANGERECORD(Base):
    __tablename__ = 'FINDINGCHANGERECORD'
    __bind_key__  = 'XORCISM'

    FindingChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FINDINGCHANGERECORD {self.FindingChangeRecordID}>'

class FINDINGCODE(Base):
    __tablename__ = 'FINDINGCODE'
    __bind_key__  = 'XORCISM'

    FindingCodeID = Column(Integer, primary_key=True)
    FindingID = Column(Integer, nullable=False)
    CodeID = Column(Integer, nullable=False)
    CodeLineID = Column(Integer)
    FindingCodeDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ImportanceID = Column(Integer)
    CriticalityLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FINDINGCODE {self.FindingCodeID}>'

class FINDINGDESCRIPTION(Base):
    __tablename__ = 'FINDINGDESCRIPTION'
    __bind_key__  = 'XORCISM'

    FindingDescriptionID = Column(Integer, primary_key=True)
    FindingDescriptionGUID = Column(Text)
    FindingID = Column(Integer, nullable=False)
    FindingGUID = Column(Text)
    DescriptionID = Column(Integer, nullable=False)
    DescriptionGUID = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FINDINGDESCRIPTION {self.FindingDescriptionID}>'

class FINDINGEVIDENCE(Base):
    __tablename__ = 'FINDINGEVIDENCE'
    __bind_key__  = 'XORCISM'

    FindingEvidenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FINDINGEVIDENCE {self.FindingEvidenceID}>'

class FINDINGHTTPSESSION(Base):
    __tablename__ = 'FINDINGHTTPSESSION'
    __bind_key__  = 'XORCISM'

    FindingHTTPSessionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FINDINGHTTPSESSION {self.FindingHTTPSessionID}>'

class FINDINGIMPACT(Base):
    __tablename__ = 'FINDINGIMPACT'
    __bind_key__  = 'XORCISM'

    FindingImpactID = Column(Integer, primary_key=True)
    FindingID = Column(Integer)
    FindingGUID = Column(Text)
    ImpactID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FINDINGIMPACT {self.FindingImpactID}>'

class FINDINGMATURITY(Base):
    __tablename__ = 'FINDINGMATURITY'
    __bind_key__  = 'XORCISM'

    FindingMaturityID = Column(Integer, primary_key=True)
    FindingID = Column(Integer)
    FindingGUID = Column(Text)
    SecurityDomainMaturityID = Column(Integer)
    SecurityDomainMaturityGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<FINDINGMATURITY {self.FindingMaturityID}>'

class FINDINGPERSON(Base):
    __tablename__ = 'FINDINGPERSON'
    __bind_key__  = 'XORCISM'

    FindingPersonID = Column(Integer, primary_key=True)
    FindingPersonGUID = Column(Text)
    FindingID = Column(Integer)
    FindingGUID = Column(Text)
    FindingPersonRelationship = Column(Text)
    FindingPersonDescription = Column(Text)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    LastCheckedDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FINDINGPERSON {self.FindingPersonID}>'

class FINDINGRACIMATRIX(Base):
    __tablename__ = 'FINDINGRACIMATRIX'
    __bind_key__  = 'XORCISM'

    FindingRACIMatrixID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FINDINGRACIMATRIX {self.FindingRACIMatrixID}>'

class FINDINGRECOMMENDATION(Base):
    __tablename__ = 'FINDINGRECOMMENDATION'
    __bind_key__  = 'XORCISM'

    FindingRecommendationID = Column(Integer, primary_key=True)
    FindingID = Column(Integer, nullable=False)
    RecommendationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    FindingRecommendationName = Column(Text)
    FindingRecommendationDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FINDINGRECOMMENDATION {self.FindingRecommendationID}>'

class FINDINGREFERENCE(Base):
    __tablename__ = 'FINDINGREFERENCE'
    __bind_key__  = 'XORCISM'

    FindingReferenceID = Column(Integer, primary_key=True)
    FindingID = Column(Integer, nullable=False)
    FindingGUID = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ImportanceID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FINDINGREFERENCE {self.FindingReferenceID}>'

class FINDINGSTATUS(Base):
    __tablename__ = 'FINDINGSTATUS'
    __bind_key__  = 'XORCISM'

    FindingStatusID = Column(Integer, primary_key=True)
    FindingStatusDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<FINDINGSTATUS {self.FindingStatusID}>'

class FINDINGTAG(Base):
    __tablename__ = 'FINDINGTAG'
    __bind_key__  = 'XORCISM'

    FindingTagID = Column(Integer, primary_key=True)
    FindingID = Column(Integer, nullable=False)
    FindingGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ImportanceID = Column(Integer)

    def __repr__(self):
        return f'<FINDINGTAG {self.FindingTagID}>'

class FINDINGVULNERABILITY(Base):
    __tablename__ = 'FINDINGVULNERABILITY'
    __bind_key__  = 'XORCISM'

    FindingVulnerabilityID = Column(Integer, primary_key=True)
    FindingID = Column(Integer)
    VulnerabilityID = Column(Integer)
    CreatedDate = Column(Text)
    FindingVulnerabilityName = Column(Text)
    FindingVulnerabilityDescription = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FINDINGVULNERABILITY {self.FindingVulnerabilityID}>'

class FIREWALLRULE(Base):
    __tablename__ = 'FIREWALLRULE'
    __bind_key__  = 'XORCISM'

    FirewallRuleID = Column(Integer, primary_key=True)
    FirewallRuleGUID = Column(Text)
    RuleID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ToolGenerationID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ReliabilityID = Column(Integer)
    ReliabilityReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    LastCheckedDate = Column(Text)
    ToolDeploymentID = Column(Integer)

    def __repr__(self):
        return f'<FIREWALLRULE {self.FirewallRuleID}>'

class FIREWALLRULEADDRESS(Base):
    __tablename__ = 'FIREWALLRULEADDRESS'
    __bind_key__  = 'XORCISM'

    FirewallRuleAddressID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FIREWALLRULEADDRESS {self.FirewallRuleAddressID}>'

class FIREWALLRULECHANGERECORD(Base):
    __tablename__ = 'FIREWALLRULECHANGERECORD'
    __bind_key__  = 'XORCISM'

    FirewallRuleChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FIREWALLRULECHANGERECORD {self.FirewallRuleChangeRecordID}>'

class FIREWALLRULECHANGEREQUEST(Base):
    __tablename__ = 'FIREWALLRULECHANGEREQUEST'
    __bind_key__  = 'XORCISM'

    FirewallRuleChangeRequestID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FIREWALLRULECHANGEREQUEST {self.FirewallRuleChangeRequestID}>'

class FIXACTION(Base):
    __tablename__ = 'FIXACTION'
    __bind_key__  = 'XORCISM'

    FixActionID = Column(Integer, primary_key=True)
    FixActionGUID = Column(Text)
    description = Column(Text)
    type = Column(Text)
    source = Column(Text)
    VocabularyID = Column(Integer)
    lang = Column(Text)
    id = Column(Text)
    reboot = Column(Integer)
    strategy = Column(Text)
    disruption = Column(Text)
    complexity = Column(Text)
    systemURI = Column(Text)
    platformURI = Column(Text)
    XCCDFContent = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FIXACTION {self.FixActionID}>'

class FIXACTIONCOST(Base):
    __tablename__ = 'FIXACTIONCOST'
    __bind_key__  = 'XORCISM'

    FixActionCostID = Column(Integer, primary_key=True)
    cost_corrective_action = Column(Text, nullable=False)

    def __repr__(self):
        return f'<FIXACTIONCOST {self.FixActionCostID}>'

class FIXACTIONFORFIXACTION(Base):
    __tablename__ = 'FIXACTIONFORFIXACTION'
    __bind_key__  = 'XORCISM'

    FixActionRelationshipID = Column(Integer, primary_key=True)
    FixActionRefID = Column(Integer, nullable=False)
    relationshiptype = Column(Text)
    FixActionSubjectID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<FIXACTIONFORFIXACTION {self.FixActionRelationshipID}>'

class FIXACTIONFORINCIDENT(Base):
    __tablename__ = 'FIXACTIONFORINCIDENT'
    __bind_key__  = 'XORCISM'

    FixActionForIncidentID = Column(Integer, primary_key=True)
    FixActionID = Column(Integer, nullable=False)
    IncidentID = Column(Integer, nullable=False)
    FixActionCostID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FIXACTIONFORINCIDENT {self.FixActionForIncidentID}>'

class FIXACTIONFORVULNERABILITY(Base):
    __tablename__ = 'FIXACTIONFORVULNERABILITY'
    __bind_key__  = 'XORCISM'

    VulnerabilityFixActionID = Column(Integer, primary_key=True)
    FixActionID = Column(Integer, nullable=False)
    FixActionGUID = Column(Text)
    VulnerabilityID = Column(Integer, nullable=False)
    VulnerabilityGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FIXACTIONFORVULNERABILITY {self.VulnerabilityFixActionID}>'

class FIXACTIONPATCH(Base):
    __tablename__ = 'FIXACTIONPATCH'
    __bind_key__  = 'XORCISM'

    FixActionPatchID = Column(Integer, primary_key=True)
    FixActionID = Column(Integer)
    FixActionGUID = Column(Text)
    FixActionPatchRelationship = Column(Text)
    FixActionPatchDescription = Column(Text)
    PatchID = Column(Integer)
    PatchGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FIXACTIONPATCH {self.FixActionPatchID}>'

class FIXSYSTEM(Base):
    __tablename__ = 'FIXSYSTEM'
    __bind_key__  = 'XORCISM'

    FixSystemID = Column(Integer, primary_key=True)
    systemURI = Column(Text, nullable=False)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FIXSYSTEM {self.FixSystemID}>'

class FLAG(Base):
    __tablename__ = 'FLAG'
    __bind_key__  = 'XORCISM'

    FlagID = Column(Integer, primary_key=True)
    FlagValue = Column(Text, nullable=False)
    FlagDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FLAG {self.FlagID}>'

class FRAMEWORK(Base):
    __tablename__ = 'FRAMEWORK'
    __bind_key__  = 'XORCISM'

    FrameworkID = Column(Integer, primary_key=True)
    FrameworkName = Column(Text, nullable=False)
    FrameworkVersion = Column(Text)
    FrameworkDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FRAMEWORK {self.FrameworkID}>'

class FRAMEWORKFORTECHNICALCONTEXT(Base):
    __tablename__ = 'FRAMEWORKFORTECHNICALCONTEXT'
    __bind_key__  = 'XORCISM'

    TechnicalContextFrameworkID = Column(Integer, primary_key=True)
    TechnicalContextFrameworkGUID = Column(Text)
    FrameworkID = Column(Integer, nullable=False)
    TechnicalContextID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FRAMEWORKFORTECHNICALCONTEXT {self.TechnicalContextFrameworkID}>'

class FRAMEWORKREFERENCE(Base):
    __tablename__ = 'FRAMEWORKREFERENCE'
    __bind_key__  = 'XORCISM'

    FrameworkReferenceID = Column(Integer, primary_key=True)
    FrameworkReferenceDescription = Column(Text)
    FrameworkID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FRAMEWORKREFERENCE {self.FrameworkReferenceID}>'

class FRAUDSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'FRAUDSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    FraudStrategicObjectiveID = Column(Integer, primary_key=True)
    FraudStrategicObjectiveName = Column(Text)
    FraudStrategicObjectiveDestruction = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FRAUDSTRATEGICOBJECTIVE {self.FraudStrategicObjectiveID}>'

class FRAUDTACTICALOBJECTIVE(Base):
    __tablename__ = 'FRAUDTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    FraudTacticalObjectiveID = Column(Integer, primary_key=True)
    FraudTacticalObjectiveName = Column(Text)
    FraudTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<FRAUDTACTICALOBJECTIVE {self.FraudTacticalObjectiveID}>'

class FREQUENCY(Base):
    __tablename__ = 'FREQUENCY'
    __bind_key__  = 'XORCISM'

    FrequencyID = Column(Integer, primary_key=True)
    rate = Column(Text, nullable=False)
    scale = Column(Text, nullable=False)
    TrendID = Column(Integer)
    TrendName = Column(Text)
    TimeUnitID = Column(Integer)
    units = Column(Text, nullable=False)

    def __repr__(self):
        return f'<FREQUENCY {self.FrequencyID}>'

class FTPACTIONNAME(Base):
    __tablename__ = 'FTPACTIONNAME'
    __bind_key__  = 'XORCISM'

    FTPActionNameID = Column(Integer, primary_key=True)
    FTPActionNameName = Column(Text, nullable=False)
    FTPActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<FTPACTIONNAME {self.FTPActionNameID}>'

class FUNCTION(Base):
    __tablename__ = 'FUNCTION'
    __bind_key__  = 'XORCISM'

    FunctionID = Column(Integer, primary_key=True)
    FunctionName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    KnownVulnerable = Column(Integer)
    deprecated = Column(Integer)
    FunctionVersion = Column(Text)
    ConfidenceLevelID = Column(Integer)
    FunctionDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<FUNCTION {self.FunctionID}>'

class FUNCTIONALAREA(Base):
    __tablename__ = 'FUNCTIONALAREA'
    __bind_key__  = 'XORCISM'

    FunctionalAreaID = Column(Integer, primary_key=True)
    FunctionalAreaGUID = Column(Text)
    FunctionalAreaName = Column(Text)
    FunctionalAreaDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ImportanceID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<FUNCTIONALAREA {self.FunctionalAreaID}>'

class FUNCTIONARGUMENT(Base):
    __tablename__ = 'FUNCTIONARGUMENT'
    __bind_key__  = 'XORCISM'

    FunctionArgumentID = Column(Integer, primary_key=True)
    FunctionID = Column(Integer)
    FunctionArgumentName = Column(Text, nullable=False)
    FunctionArgumentDescription = Column(Text)
    FunctionArgumentType = Column(Text)

    def __repr__(self):
        return f'<FUNCTIONARGUMENT {self.FunctionArgumentID}>'

class FUNCTIONCHARACTERDELIMITER(Base):
    __tablename__ = 'FUNCTIONCHARACTERDELIMITER'
    __bind_key__  = 'XORCISM'

    FunctionCharacterDelimiterID = Column(Integer, primary_key=True)
    FunctionID = Column(Integer, nullable=False)
    CharacterDelimiterID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<FUNCTIONCHARACTERDELIMITER {self.FunctionCharacterDelimiterID}>'

class FUNCTIONDESCRIPTION(Base):
    __tablename__ = 'FUNCTIONDESCRIPTION'
    __bind_key__  = 'XORCISM'

    FunctionDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FUNCTIONDESCRIPTION {self.FunctionDescriptionID}>'

class FUNCTIONREFERENCE(Base):
    __tablename__ = 'FUNCTIONREFERENCE'
    __bind_key__  = 'XORCISM'

    FunctionReferenceID = Column(Integer, primary_key=True)
    FunctionID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    FunctionReferenceDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<FUNCTIONREFERENCE {self.FunctionReferenceID}>'

class FUNCTIONRELATIONSHIP(Base):
    __tablename__ = 'FUNCTIONRELATIONSHIP'
    __bind_key__  = 'XORCISM'

    FunctionRelationshipID = Column(Integer, primary_key=True)
    FunctionRelationshipGUID = Column(Text)
    FunctionParentID = Column(Integer, nullable=False)
    FunctionSubjectID = Column(Integer, nullable=False)
    FunctionRelationshipDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<FUNCTIONRELATIONSHIP {self.FunctionRelationshipID}>'

class FUNCTIONRELATIONSHIPREFERENCE(Base):
    __tablename__ = 'FUNCTIONRELATIONSHIPREFERENCE'
    __bind_key__  = 'XORCISM'

    FunctionRelationshipReferenceID = Column(Integer, primary_key=True)
    FunctionRelationshipGUID = Column(Text)
    FunctionRelationshipID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<FUNCTIONRELATIONSHIPREFERENCE {self.FunctionRelationshipReferenceID}>'

class FUNCTIONTAG(Base):
    __tablename__ = 'FUNCTIONTAG'
    __bind_key__  = 'XORCISM'

    FunctionTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<FUNCTIONTAG {self.FunctionTagID}>'

class GEOLOCATION(Base):
    __tablename__ = 'GEOLOCATION'
    __bind_key__  = 'XORCISM'

    GeoLocationID = Column(Integer, primary_key=True)
    GeoLocationGUID = Column(Text)
    room_identifier = Column(Text)
    building_number = Column(Text)
    street_address = Column(Text)
    city = Column(Text)
    state = Column(Text)
    postal_code = Column(Text)
    country = Column(Text)
    latitude = Column(Integer)
    longitude = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CreationObjectGUID = Column(Text)
    BLOB = Column(Text, nullable=False)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionMethodGUID = Column(Text)
    isEncrypted = Column(Integer)
    LastCheckedDate = Column(Text)

    def __repr__(self):
        return f'<GEOLOCATION {self.GeoLocationID}>'

class GOOGLEDORK(Base):
    __tablename__ = 'GOOGLEDORK'
    __bind_key__  = 'XORCISM'

    GoogleDorkID = Column(Integer, primary_key=True)
    DorkValue = Column(Text)
    DorkExpectedPattern = Column(Text)
    DorkDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<GOOGLEDORK {self.GoogleDorkID}>'

class GOOGLEDORKURI(Base):
    __tablename__ = 'GOOGLEDORKURI'
    __bind_key__  = 'XORCISM'

    GoogleDorkURIID = Column(Integer, primary_key=True)
    GoogleDorkID = Column(Integer, nullable=False)
    URIObjectID = Column(Integer, nullable=False)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<GOOGLEDORKURI {self.GoogleDorkURIID}>'

class GROUP(Base):
    __tablename__ = 'GROUP'
    __bind_key__  = 'XORCISM'

    GoogleDorkURIID = Column(Integer, primary_key=True)
    GoogleDorkID = Column(Integer, nullable=False)
    URIObjectID = Column(Integer, nullable=False)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<GROUP {self.GoogleDorkURIID}>'

class GROUPINGRELATIONSHIP(Base):
    __tablename__ = 'GROUPINGRELATIONSHIP'
    __bind_key__  = 'XORCISM'

    GroupingRelationshipID = Column(Integer, primary_key=True)
    GroupingRelationshipName = Column(Text, nullable=False)
    GroupingRelationshipDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<GROUPINGRELATIONSHIP {self.GroupingRelationshipID}>'

class GUIACTIONNAME(Base):
    __tablename__ = 'GUIACTIONNAME'
    __bind_key__  = 'XORCISM'

    GUIActionNameID = Column(Integer, primary_key=True)
    GUIActionNameName = Column(Text, nullable=False)
    GUIActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<GUIACTIONNAME {self.GUIActionNameID}>'

class GUIDELINE(Base):
    __tablename__ = 'GUIDELINE'
    __bind_key__  = 'XORCISM'

    GuidelineID = Column(Integer, primary_key=True)
    GuidelineGUID = Column(Text)
    GuidelineText = Column(Text, nullable=False)
    GuidelineDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<GUIDELINE {self.GuidelineID}>'

class GUIDELINEFORATTACKPATTERN(Base):
    __tablename__ = 'GUIDELINEFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternGuidelineID = Column(Integer, primary_key=True)
    GuidelineID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer, nullable=False)
    capec_id = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<GUIDELINEFORATTACKPATTERN {self.AttackPatternGuidelineID}>'

class GUIDIALOGBOX(Base):
    __tablename__ = 'GUIDIALOGBOX'
    __bind_key__  = 'XORCISM'

    GUIDialogboxID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<GUIDIALOGBOX {self.GUIDialogboxID}>'

class GUIOBJECT(Base):
    __tablename__ = 'GUIOBJECT'
    __bind_key__  = 'XORCISM'

    GUIObjectID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<GUIOBJECT {self.GUIObjectID}>'

class GUIWINDOW(Base):
    __tablename__ = 'GUIWINDOW'
    __bind_key__  = 'XORCISM'

    GUIWindowID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<GUIWINDOW {self.GUIWindowID}>'

class HANDLETYPE(Base):
    __tablename__ = 'HANDLETYPE'
    __bind_key__  = 'XORCISM'

    HandleTypeID = Column(Integer, primary_key=True)
    HandleType = Column(Text, nullable=False)
    HandleTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<HANDLETYPE {self.HandleTypeID}>'

class HARDWARE(Base):
    __tablename__ = 'HARDWARE'
    __bind_key__  = 'XORCISM'

    HardwareID = Column(Integer, primary_key=True)
    DeviceID = Column(Integer)

    def __repr__(self):
        return f'<HARDWARE {self.HardwareID}>'

class HASHLIST(Base):
    __tablename__ = 'HASHLIST'
    __bind_key__  = 'XORCISM'

    HashListID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    RepositoryID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<HASHLIST {self.HashListID}>'

class HASHLISTVALUES(Base):
    __tablename__ = 'HASHLISTVALUES'
    __bind_key__  = 'XORCISM'

    HashListValuesID = Column(Integer, primary_key=True)
    HashListID = Column(Integer, nullable=False)
    HashValueID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<HASHLISTVALUES {self.HashListValuesID}>'

class HASHNAME(Base):
    __tablename__ = 'HASHNAME'
    __bind_key__  = 'XORCISM'

    HashNameID = Column(Integer, primary_key=True)
    HashingAlgorithmName = Column(Text, nullable=False)
    HashingAlgorithmDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<HASHNAME {self.HashNameID}>'

class HASHVALUE(Base):
    __tablename__ = 'HASHVALUE'
    __bind_key__  = 'XORCISM'

    HashValueID = Column(Integer, primary_key=True)
    HashNameID = Column(Integer)
    HashValueValue = Column(Text, nullable=False)
    CollectedDate = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    RepositoryID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HASHVALUE {self.HashValueID}>'

class HEADER(Base):
    __tablename__ = 'HEADER'
    __bind_key__  = 'XORCISM'

    HeaderID = Column(Integer, primary_key=True)
    HeaderGUID = Column(Text)
    HeaderName = Column(Text)
    HeaderDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HEADER {self.HeaderID}>'

class HEADERDESCRIPTION(Base):
    __tablename__ = 'HEADERDESCRIPTION'
    __bind_key__  = 'XORCISM'

    HeaderDescriptionID = Column(Integer, primary_key=True)
    HeaderID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HEADERDESCRIPTION {self.HeaderDescriptionID}>'

class HEADERREFERENCE(Base):
    __tablename__ = 'HEADERREFERENCE'
    __bind_key__  = 'XORCISM'

    HeaderReferenceID = Column(Integer, primary_key=True)
    HeaderID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<HEADERREFERENCE {self.HeaderReferenceID}>'

class HEADERTAG(Base):
    __tablename__ = 'HEADERTAG'
    __bind_key__  = 'XORCISM'

    HeaderTagID = Column(Integer, primary_key=True)
    HeaderID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<HEADERTAG {self.HeaderTagID}>'

class HIVELIST(Base):
    __tablename__ = 'HIVELIST'
    __bind_key__  = 'XORCISM'

    HiveListID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<HIVELIST {self.HiveListID}>'

class HOOKING(Base):
    __tablename__ = 'HOOKING'
    __bind_key__  = 'XORCISM'

    HookingID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<HOOKING {self.HookingID}>'

class HOOKINGACTIONNAME(Base):
    __tablename__ = 'HOOKINGACTIONNAME'
    __bind_key__  = 'XORCISM'

    HookingActionNameID = Column(Integer, primary_key=True)
    HookingActionNameName = Column(Text, nullable=False)
    HookingActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<HOOKINGACTIONNAME {self.HookingActionNameID}>'

class HOST(Base):
    __tablename__ = 'HOST'
    __bind_key__  = 'XORCISM'

    HostID = Column(Integer, primary_key=True)
    ipaddressIPv4 = Column(Text)
    macaddress = Column(Text)
    OsName = Column(Text)
    HostService = Column(Text)
    HostVersion = Column(Text)
    BLOB = Column(Text)
    CPEID = Column(Integer)

    def __repr__(self):
        return f'<HOST {self.HostID}>'

class HOSTENDPOINT(Base):
    __tablename__ = 'HOSTENDPOINT'
    __bind_key__  = 'XORCISM'

    HostEndPointID = Column(Integer, primary_key=True)
    HostPort = Column(Integer)
    HostProtocol = Column(Text)
    HostID = Column(Integer)
    HostService = Column(Text)
    HostVersion = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<HOSTENDPOINT {self.HostEndPointID}>'

class HOSTFIELD(Base):
    __tablename__ = 'HOSTFIELD'
    __bind_key__  = 'XORCISM'

    HostFieldID = Column(Integer, primary_key=True)
    Domain_Name = Column(Text)
    Port = Column(Integer)
    PortID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<HOSTFIELD {self.HostFieldID}>'

class HOSTNAME(Base):
    __tablename__ = 'HOSTNAME'
    __bind_key__  = 'XORCISM'

    HostNameID = Column(Integer, primary_key=True)
    HostNameGUID = Column(Text)
    is_domain_name = Column(Integer)
    Hostname_Value = Column(Text)
    Naming_System = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<HOSTNAME {self.HostNameID}>'

class HTTPACTIONNAME(Base):
    __tablename__ = 'HTTPACTIONNAME'
    __bind_key__  = 'XORCISM'

    HTTPActionNameID = Column(Integer, primary_key=True)
    HTTPActionNameName = Column(Text, nullable=False)
    HTTPActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HTTPACTIONNAME {self.HTTPActionNameID}>'

class HTTPCLIENTREQUEST(Base):
    __tablename__ = 'HTTPCLIENTREQUEST'
    __bind_key__  = 'XORCISM'

    HTTPClientRequestID = Column(Integer, primary_key=True)
    HTTPClientRequestGUID = Column(Text)
    HTTP_Request_Line = Column(Integer)
    HTTP_Request_Header = Column(Integer)
    HTTP_Message_Body = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<HTTPCLIENTREQUEST {self.HTTPClientRequestID}>'

class HTTPHEADER(Base):
    __tablename__ = 'HTTPHEADER'
    __bind_key__  = 'XORCISM'

    HTTPHeaderID = Column(Integer, primary_key=True)
    HTTPHeaderGUID = Column(Text)
    HeaderID = Column(Integer)
    HTTPHeaderName = Column(Text)
    HTTPHeaderDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HTTPHEADER {self.HTTPHeaderID}>'

class HTTPHEADERCPE(Base):
    __tablename__ = 'HTTPHEADERCPE'
    __bind_key__  = 'XORCISM'

    HTTPHeaderCPEID = Column(Integer, primary_key=True)
    CPEID = Column(Integer)
    CPEName = Column(Text, nullable=False)
    HTTPHeaderID = Column(Integer, nullable=False)
    isspecific = Column(Integer)
    isknownvulnerable = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    VocabularyID = Column(Integer)
    ReferenceID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HTTPHEADERCPE {self.HTTPHeaderCPEID}>'

class HTTPHEADERDESCRIPTION(Base):
    __tablename__ = 'HTTPHEADERDESCRIPTION'
    __bind_key__  = 'XORCISM'

    HTTPHeaderDescriptionID = Column(Integer, primary_key=True)
    HTTPHeaderID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<HTTPHEADERDESCRIPTION {self.HTTPHeaderDescriptionID}>'

class HTTPHEADERPRODUCT(Base):
    __tablename__ = 'HTTPHEADERPRODUCT'
    __bind_key__  = 'XORCISM'

    HTTPHeaderProductID = Column(Integer, primary_key=True)
    HTTPHeaderID = Column(Integer)
    HTTPHeaderGUID = Column(Text)
    ProductID = Column(Integer)
    ProductGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<HTTPHEADERPRODUCT {self.HTTPHeaderProductID}>'

class HTTPMESSAGE(Base):
    __tablename__ = 'HTTPMESSAGE'
    __bind_key__  = 'XORCISM'

    HTTPMessageID = Column(Integer, primary_key=True)
    MessageID = Column(Integer)
    Length = Column(Integer)
    Message_Body = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    DiscoveryMethodID = Column(Integer)
    DiscoveryToolID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HTTPMESSAGE {self.HTTPMessageID}>'

class HTTPMETHOD(Base):
    __tablename__ = 'HTTPMETHOD'
    __bind_key__  = 'XORCISM'

    HTTPMethodID = Column(Integer, primary_key=True)
    HTTPMethodEnumID = Column(Integer)

    def __repr__(self):
        return f'<HTTPMETHOD {self.HTTPMethodID}>'

class HTTPMETHODENUM(Base):
    __tablename__ = 'HTTPMETHODENUM'
    __bind_key__  = 'XORCISM'

    HTTPMethodEnumID = Column(Integer, primary_key=True)
    HTTPMethodName = Column(Text)
    HTTPMethodDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    knowndangerous = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HTTPMETHODENUM {self.HTTPMethodEnumID}>'

class HTTPREQUESTHEADER(Base):
    __tablename__ = 'HTTPREQUESTHEADER'
    __bind_key__  = 'XORCISM'

    HTTPRequestHeaderID = Column(Integer, primary_key=True)
    Raw_Header = Column(Text)
    Parsed_Header = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<HTTPREQUESTHEADER {self.HTTPRequestHeaderID}>'

class HTTPREQUESTHEADERFIELDS(Base):
    __tablename__ = 'HTTPREQUESTHEADERFIELDS'
    __bind_key__  = 'XORCISM'

    HTTPRequestHeaderFieldsID = Column(Integer, primary_key=True)
    Accept = Column(Text)
    Accept_Charset = Column(Text)
    Accept_Language = Column(Text)
    Accept_Datetime = Column(Text)
    Accept_Encoding = Column(Text)
    AuthorizationHeader = Column(Text)
    Cache_Control = Column(Text)
    Connection = Column(Text)
    Cookie = Column(Text)
    CookieID = Column(Integer)
    Content_Length = Column(Integer)
    Content_MD5 = Column(Text)
    Content_Type = Column(Text)
    ContentMIMEID = Column(Integer)
    TEXT = Column(Text)
    Expect = Column(Text)
    FromHeader = Column(Text)
    FromEmailAddressID = Column(Integer)
    HostFieldID = Column(Integer)
    If_Match = Column(Text)
    If_Modified_Since = Column(Text)
    If_None_Match = Column(Text)
    If_Range = Column(Text)
    If_Unmodified_Since = Column(Text)
    Max_Forwards = Column(Integer)
    Pragma = Column(Text)
    Proxy_Authorization = Column(Text)
    Range = Column(Text)
    Referer = Column(Text)
    RefererURIID = Column(Integer)
    TE = Column(Text)
    User_Agent = Column(Text)
    UserAgentID = Column(Integer)
    Via = Column(Text)
    Warning = Column(Text)
    DNT = Column(Text)
    X_Requested_With = Column(Text)
    X_Forwarded_For = Column(Text)
    X_ATT_DeviceId = Column(Text)
    X_Wap_Profile = Column(Text)
    X_Wap_ProfileURIID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<HTTPREQUESTHEADERFIELDS {self.HTTPRequestHeaderFieldsID}>'

class HTTPREQUESTLINE(Base):
    __tablename__ = 'HTTPREQUESTLINE'
    __bind_key__  = 'XORCISM'

    HTTPRequestLineID = Column(Integer, primary_key=True)
    HTTP_Method = Column(Integer)
    Value = Column(Text)
    Version = Column(Text)
    CreationDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<HTTPREQUESTLINE {self.HTTPRequestLineID}>'

class HTTPREQUESTRESPONSE(Base):
    __tablename__ = 'HTTPREQUESTRESPONSE'
    __bind_key__  = 'XORCISM'

    HTTPRequestResponseID = Column(Integer, primary_key=True)
    HTTPRequestResponseGUID = Column(Text)
    HTTP_Client_Request = Column(Integer)
    HTTP_Server_Response = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<HTTPREQUESTRESPONSE {self.HTTPRequestResponseID}>'

class HTTPRESPONSEHEADER(Base):
    __tablename__ = 'HTTPRESPONSEHEADER'
    __bind_key__  = 'XORCISM'

    HTTPResponseHeaderID = Column(Integer, primary_key=True)
    Raw_Header = Column(Text)
    Parsed_Header = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)

    def __repr__(self):
        return f'<HTTPRESPONSEHEADER {self.HTTPResponseHeaderID}>'

class HTTPRESPONSEHEADERFIELDS(Base):
    __tablename__ = 'HTTPRESPONSEHEADERFIELDS'
    __bind_key__  = 'XORCISM'

    HTTPResponseHeaderFieldsID = Column(Integer, primary_key=True)
    Access_Control_Allow_Origin = Column(Text)
    Accept_Ranges = Column(Text)
    Age = Column(Integer)
    Cache_Control = Column(Text)
    Connection = Column(Text)
    Content_Encoding = Column(Text)
    Content_Language = Column(Text)
    Content_Length = Column(Integer)
    Content_Location = Column(Text)
    Content_MD5 = Column(Text)
    Content_Disposition = Column(Text)
    Content_Range = Column(Text)
    Content_Type = Column(Text)
    ContentMIMEID = Column(Integer)
    TEXT = Column(Text)
    ETag = Column(Text)
    Expires = Column(Text)
    Last_Modified = Column(Text)
    Link = Column(Text)
    Location = Column(Text)
    LocationURIID = Column(Integer)
    P3P = Column(Text)
    Pragma = Column(Text)
    Proxy_Authenticate = Column(Text)
    Refresh = Column(Integer)
    Retry_After = Column(Integer)
    Server = Column(Text)
    Set_Cookie = Column(Text)
    Strict_Transport_Security = Column(Text)
    Trailer = Column(Text)
    Transfer_Encoding = Column(Text)
    Vary = Column(Text)
    VaryURIID = Column(Integer)
    Via = Column(Text)
    Warning = Column(Text)
    WWW_Authenticate = Column(Text)
    X_Frame_Options = Column(Text)
    X_XSS_Protection = Column(Text)
    X_Content_Type_Options = Column(Text)
    X_Forwarded_Proto = Column(Text)
    X_Powered_By = Column(Text)
    X_UA_Compatible = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<HTTPRESPONSEHEADERFIELDS {self.HTTPResponseHeaderFieldsID}>'

class HTTPSERVERRESPONSE(Base):
    __tablename__ = 'HTTPSERVERRESPONSE'
    __bind_key__  = 'XORCISM'

    HTTPServerResponseID = Column(Integer, primary_key=True)
    HTTP_Status_Line = Column(Integer)
    HTTP_Response_Header = Column(Integer)
    HTTP_Message_Body = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)

    def __repr__(self):
        return f'<HTTPSERVERRESPONSE {self.HTTPServerResponseID}>'

class HTTPSESSION(Base):
    __tablename__ = 'HTTPSESSION'
    __bind_key__  = 'XORCISM'

    HTTPSessionID = Column(Integer, primary_key=True)
    HTTPSessionGUID = Column(Text)
    SessionID = Column(Integer)
    SessionGUID = Column(Text)
    HTTP_Request_ResponseID = Column(Integer)
    HTTPRequestResponseGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<HTTPSESSION {self.HTTPSessionID}>'

class HTTPSESSIONCOOKIE(Base):
    __tablename__ = 'HTTPSESSIONCOOKIE'
    __bind_key__  = 'XORCISM'

    HTTPSessionCookieID = Column(Integer, primary_key=True)
    HTTPSessionCookieGUID = Column(Text)
    HTTPSessionID = Column(Integer)
    HTTPSessionGUID = Column(Text)
    HTTPSessionCookieRelationship = Column(Text)
    HTTPSessionDescription = Column(Text)
    CookieID = Column(Integer)
    CookieGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HTTPSESSIONCOOKIE {self.HTTPSessionCookieID}>'

class HTTPSTATUSLINE(Base):
    __tablename__ = 'HTTPSTATUSLINE'
    __bind_key__  = 'XORCISM'

    HTTPStatusLineID = Column(Integer, primary_key=True)
    Version = Column(Text)
    VersionID = Column(Integer)
    Status_Code = Column(Integer)
    Reason_Phrase = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<HTTPSTATUSLINE {self.HTTPStatusLineID}>'

class HUMANRISK(Base):
    __tablename__ = 'HUMANRISK'
    __bind_key__  = 'XORCISM'

    HumanRiskID = Column(Integer, primary_key=True)
    HumanRiskName = Column(Text, nullable=False)
    HumanRiskDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<HUMANRISK {self.HumanRiskID}>'

class ICOMHANDLERACTION(Base):
    __tablename__ = 'ICOMHANDLERACTION'
    __bind_key__  = 'XORCISM'

    IComHandlerActionID = Column(Integer, primary_key=True)
    COM_Data = Column(Text)
    COM_Class_ID = Column(Text)

    def __repr__(self):
        return f'<ICOMHANDLERACTION {self.IComHandlerActionID}>'

class IDENTIFICATIONSYSTEM(Base):
    __tablename__ = 'IDENTIFICATIONSYSTEM'
    __bind_key__  = 'XORCISM'

    IdentificationSystemID = Column(Integer, primary_key=True)
    SystemURI = Column(Text, nullable=False)
    IdentifierValueDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<IDENTIFICATIONSYSTEM {self.IdentificationSystemID}>'

class IDENTIFIER(Base):
    __tablename__ = 'IDENTIFIER'
    __bind_key__  = 'XORCISM'

    IdentifierID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<IDENTIFIER {self.IdentifierID}>'

class IDTENTRY(Base):
    __tablename__ = 'IDTENTRY'
    __bind_key__  = 'XORCISM'

    IDTEntryID = Column(Integer, primary_key=True)
    Type_Attr = Column(Text)
    Offset_High = Column(Text)
    Offset_Low = Column(Text)
    Offset_Middle = Column(Text)
    Selector = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)

    def __repr__(self):
        return f'<IDTENTRY {self.IDTEntryID}>'

class IDTENTRYLIST(Base):
    __tablename__ = 'IDTENTRYLIST'
    __bind_key__  = 'XORCISM'

    IDTEntryListID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<IDTENTRYLIST {self.IDTEntryListID}>'

class IDTENTRYLISTENTRIES(Base):
    __tablename__ = 'IDTENTRYLISTENTRIES'
    __bind_key__  = 'XORCISM'

    IDTEntryListEntriesID = Column(Integer, primary_key=True)
    IDTEntryListID = Column(Integer, nullable=False)
    IDTEntryID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)

    def __repr__(self):
        return f'<IDTENTRYLISTENTRIES {self.IDTEntryListEntriesID}>'

class IEXECACTION(Base):
    __tablename__ = 'IEXECACTION'
    __bind_key__  = 'XORCISM'

    IExecActionID = Column(Integer, primary_key=True)
    Exec_Arguments = Column(Text)
    Exec_Program_Path = Column(Text)
    Exec_Working_Directory = Column(Text)
    DirectoryID = Column(Integer)
    Exec_Program_Hashes = Column(Text)
    HashListID = Column(Integer)

    def __repr__(self):
        return f'<IEXECACTION {self.IExecActionID}>'

class IMAGEFILE(Base):
    __tablename__ = 'IMAGEFILE'
    __bind_key__  = 'XORCISM'

    ImageFileID = Column(Integer, primary_key=True)
    FileID = Column(Integer)
    ImageFileFormatID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    image_is_compressed = Column(Integer)
    Image_Height = Column(Integer)
    Image_Width = Column(Integer)
    Bits_Per_Pixel = Column(Integer)
    Compression_Algorithm = Column(Text)
    CompressionID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<IMAGEFILE {self.ImageFileID}>'

class IMAGEFILEEXIFTAG(Base):
    __tablename__ = 'IMAGEFILEEXIFTAG'
    __bind_key__  = 'XORCISM'

    ImageFileEXIFTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<IMAGEFILEEXIFTAG {self.ImageFileEXIFTagID}>'

class IMAGEFILEFORMAT(Base):
    __tablename__ = 'IMAGEFILEFORMAT'
    __bind_key__  = 'XORCISM'

    ImageFileFormatID = Column(Integer, primary_key=True)
    ImageFileFormatName = Column(Text)
    ImageFileFormatDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<IMAGEFILEFORMAT {self.ImageFileFormatID}>'

class IMAGEFILETYPE(Base):
    __tablename__ = 'IMAGEFILETYPE'
    __bind_key__  = 'XORCISM'

    ImageFileTypeID = Column(Integer, primary_key=True)
    ImageFileTypeName = Column(Text)
    ImageFileTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<IMAGEFILETYPE {self.ImageFileTypeID}>'

class IMPACT(Base):
    __tablename__ = 'IMPACT'
    __bind_key__  = 'XORCISM'

    ImpactID = Column(Integer, primary_key=True)
    TechnicalImpact = Column(Integer)
    BusinessImpact = Column(Integer)
    ImpactName = Column(Text)
    ImpactDescription = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<IMPACT {self.ImpactID}>'

class IMPACTQUALIFICATION(Base):
    __tablename__ = 'IMPACTQUALIFICATION'
    __bind_key__  = 'XORCISM'

    ImpactQualificationID = Column(Integer, primary_key=True)
    ImpactQualificationName = Column(Text)
    ImpactQualificationDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<IMPACTQUALIFICATION {self.ImpactQualificationID}>'

class IMPACTRATING(Base):
    __tablename__ = 'IMPACTRATING'
    __bind_key__  = 'XORCISM'

    ImpactRatingID = Column(Integer, primary_key=True)
    ImpactRatingName = Column(Text)
    ImpactRatingDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<IMPACTRATING {self.ImpactRatingID}>'

class IMPORTANCE(Base):
    __tablename__ = 'IMPORTANCE'
    __bind_key__  = 'XORCISM'

    ImportanceID = Column(Integer, primary_key=True)
    ImportanceGUID = Column(Text)
    ImportanceLevel = Column(Text)
    ImportanceDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<IMPORTANCE {self.ImportanceID}>'

class IMPORTANCETYPE(Base):
    __tablename__ = 'IMPORTANCETYPE'
    __bind_key__  = 'XORCISM'

    ImportanceTypeID = Column(Integer, primary_key=True)
    ImportanceTypeName = Column(Text, nullable=False)
    ImportanceTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<IMPORTANCETYPE {self.ImportanceTypeID}>'

class INDICATOR(Base):
    __tablename__ = 'INDICATOR'
    __bind_key__  = 'XORCISM'

    IndicatorID = Column(Integer, primary_key=True)
    IndicatorGUID = Column(Text)
    IndicatorTitle = Column(Text, nullable=False)
    IndicatorDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceLevel = Column(Text)
    ConfidenceReasonID = Column(Integer)
    LikelyImpact = Column(Text)
    Producer = Column(Text)
    negate = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ImportanceID = Column(Integer)

    def __repr__(self):
        return f'<INDICATOR {self.IndicatorID}>'

class INDICATORENVIRONMENT(Base):
    __tablename__ = 'INDICATORENVIRONMENT'
    __bind_key__  = 'XORCISM'

    IndicatorEnvironmentID = Column(Integer, primary_key=True)
    IndicatorEnvironmentGUID = Column(Text)
    IndicatorID = Column(Integer)
    IndicatorGUID = Column(Text)
    EnvironmentID = Column(Integer)
    EnvironmentGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INDICATORENVIRONMENT {self.IndicatorEnvironmentID}>'

class INDICATORFORINDICATOR(Base):
    __tablename__ = 'INDICATORFORINDICATOR'
    __bind_key__  = 'XORCISM'

    IndicatorRefID = Column(Integer, primary_key=True)
    IndicatorSubjectID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INDICATORFORINDICATOR {self.IndicatorRefID}>'

class INDICATORID(Base):
    __tablename__ = 'INDICATORID'
    __bind_key__  = 'XORCISM'

    IndicatorIDID = Column(Integer, primary_key=True)
    IndicatorAlternativeID = Column(Text, nullable=False)
    resource = Column(Text)

    def __repr__(self):
        return f'<INDICATORID {self.IndicatorIDID}>'

class INDICATORIDFORINCIDENTIOC(Base):
    __tablename__ = 'INDICATORIDFORINCIDENTIOC'
    __bind_key__  = 'XORCISM'

    IndicatorIDID = Column(Integer, primary_key=True)
    IncidentIOCID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INDICATORIDFORINCIDENTIOC {self.IndicatorIDID}>'

class INDICATORIDFORINDICATOR(Base):
    __tablename__ = 'INDICATORIDFORINDICATOR'
    __bind_key__  = 'XORCISM'

    IndicatorIDID = Column(Integer, primary_key=True)
    IndicatorID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INDICATORIDFORINDICATOR {self.IndicatorIDID}>'

class INDICATORTESTMECHANISM(Base):
    __tablename__ = 'INDICATORTESTMECHANISM'
    __bind_key__  = 'XORCISM'

    IndicatorTestMechanismID = Column(Integer, primary_key=True)
    IndicatorID = Column(Integer)
    TestMechanismID = Column(Integer)
    Product_Name = Column(Text)
    Version = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INDICATORTESTMECHANISM {self.IndicatorTestMechanismID}>'

class INDICATORTESTMECHANISMCPE(Base):
    __tablename__ = 'INDICATORTESTMECHANISMCPE'
    __bind_key__  = 'XORCISM'

    IndicatorTestMechanismCPEID = Column(Integer, primary_key=True)
    IndicatorTestMechanismID = Column(Integer)
    CPEID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CreationObjectID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)

    def __repr__(self):
        return f'<INDICATORTESTMECHANISMCPE {self.IndicatorTestMechanismCPEID}>'

class INDICATORTESTMECHANISMEVENTFILTER(Base):
    __tablename__ = 'INDICATORTESTMECHANISMEVENTFILTER'
    __bind_key__  = 'XORCISM'

    IndicatorTestMechanismEventFilterID = Column(Integer, primary_key=True)
    IndicatorTestMechanismID = Column(Integer)
    EventFilterID = Column(Integer)
    RuleID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INDICATORTESTMECHANISMEVENTFILTER {self.IndicatorTestMechanismEventFilterID}>'

class INDICATORTESTMECHANISMEVENTSUPPRESSION(Base):
    __tablename__ = 'INDICATORTESTMECHANISMEVENTSUPPRESSION'
    __bind_key__  = 'XORCISM'

    IndicatorTestMechanismEventSuppressionID = Column(Integer, primary_key=True)
    IndicatorTestMechanismID = Column(Integer)
    EventSuppressionID = Column(Integer)
    RuleID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INDICATORTESTMECHANISMEVENTSUPPRESSION {self.IndicatorTestMechanismEventSuppressionID}>'

class INDICATORTESTMECHANISMRATEFILTER(Base):
    __tablename__ = 'INDICATORTESTMECHANISMRATEFILTER'
    __bind_key__  = 'XORCISM'

    IndicatorTestMechanismRateFilterID = Column(Integer, primary_key=True)
    IndicatorTestMechanismID = Column(Integer)
    RateFilterID = Column(Integer)
    RuleID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INDICATORTESTMECHANISMRATEFILTER {self.IndicatorTestMechanismRateFilterID}>'

class INDICATORTESTMECHANISMRULE(Base):
    __tablename__ = 'INDICATORTESTMECHANISMRULE'
    __bind_key__  = 'XORCISM'

    IndicatorTestMechanismRuleID = Column(Integer, primary_key=True)
    IndicatorTestMechanismID = Column(Integer)
    RuleID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<INDICATORTESTMECHANISMRULE {self.IndicatorTestMechanismRuleID}>'

class INDICATORTYPE(Base):
    __tablename__ = 'INDICATORTYPE'
    __bind_key__  = 'XORCISM'

    IndicatorTypeID = Column(Integer, primary_key=True)
    IndicatorTypeGUID = Column(Text)
    IndicatorTypeName = Column(Text)
    IndicatorTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<INDICATORTYPE {self.IndicatorTypeID}>'

class INFECTIONPROPAGATIONPROPERTIES(Base):
    __tablename__ = 'INFECTIONPROPAGATIONPROPERTIES'
    __bind_key__  = 'XORCISM'

    InfectionPropagationPropertiesID = Column(Integer, primary_key=True)
    InfectionPropagationPropertiesName = Column(Text)
    InfectionPropagationPropertiesDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<INFECTIONPROPAGATIONPROPERTIES {self.InfectionPropagationPropertiesID}>'

class INFECTIONPROPAGATIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'INFECTIONPROPAGATIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    InfectionPropagationStrategicObjectiveID = Column(Integer, primary_key=True)
    InfectionPropagationStrategicObjectiveName = Column(Text)
    InfectionPropagationStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INFECTIONPROPAGATIONSTRATEGICOBJECTIVE {self.InfectionPropagationStrategicObjectiveID}>'

class INFECTIONPROPAGATIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'INFECTIONPROPAGATIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    InfectionPropagationTacticalObjectiveID = Column(Integer, primary_key=True)
    InfectionPropagationTacticalObjectiveName = Column(Text)
    InfectionPropagationTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INFECTIONPROPAGATIONTACTICALOBJECTIVE {self.InfectionPropagationTacticalObjectiveID}>'

class INFLUENCE(Base):
    __tablename__ = 'INFLUENCE'
    __bind_key__  = 'XORCISM'

    InfluenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<INFLUENCE {self.InfluenceID}>'

class INFORMATIONSOURCEROLE(Base):
    __tablename__ = 'INFORMATIONSOURCEROLE'
    __bind_key__  = 'XORCISM'

    InformationSourceRoleID = Column(Integer, primary_key=True)
    InformationSourceRoleGUID = Column(Text)
    InformationSourceRoleName = Column(Text)
    InformationSourceRoleDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<INFORMATIONSOURCEROLE {self.InformationSourceRoleID}>'

class INFORMATIONSOURCETYPE(Base):
    __tablename__ = 'INFORMATIONSOURCETYPE'
    __bind_key__  = 'XORCISM'

    InformationSourceTypeID = Column(Integer, primary_key=True)
    InformationSourceTypeGUID = Column(Text)
    InformationSourceTypeName = Column(Text, nullable=False)
    InformationSourceTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<INFORMATIONSOURCETYPE {self.InformationSourceTypeID}>'

class INFORMATIONTYPE(Base):
    __tablename__ = 'INFORMATIONTYPE'
    __bind_key__  = 'XORCISM'

    InformationTypeID = Column(Integer, primary_key=True)
    InformationTypeGUID = Column(Text)
    InformationTypeName = Column(Text, nullable=False)
    InformationTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INFORMATIONTYPE {self.InformationTypeID}>'

class INFORMATIONTYPEFORTHREATACTORTTP(Base):
    __tablename__ = 'INFORMATIONTYPEFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    InformationTypeID = Column(Integer, primary_key=True)
    ThreatActorTTPID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INFORMATIONTYPEFORTHREATACTORTTP {self.InformationTypeID}>'

class INFRASTRUCTURE(Base):
    __tablename__ = 'INFRASTRUCTURE'
    __bind_key__  = 'XORCISM'

    InfrastructureID = Column(Integer, primary_key=True)
    InfrastructureGUID = Column(Text)
    isCritical = Column(Integer)

    def __repr__(self):
        return f'<INFRASTRUCTURE {self.InfrastructureID}>'

class INJECTIONVECTOR(Base):
    __tablename__ = 'INJECTIONVECTOR'
    __bind_key__  = 'XORCISM'

    InjectionVectorID = Column(Integer, primary_key=True)
    InjectionVectorGUID = Column(Text)
    InjectionVectorText = Column(Text, nullable=False)
    InjectionVectorDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<INJECTIONVECTOR {self.InjectionVectorID}>'

class INJECTIONVECTORFORATTACKPATTERN(Base):
    __tablename__ = 'INJECTIONVECTORFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternInjectionVectorID = Column(Integer, primary_key=True)
    InjectionVectorID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer, nullable=False)
    capec_id = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INJECTIONVECTORFORATTACKPATTERN {self.AttackPatternInjectionVectorID}>'

class INSTANCE(Base):
    __tablename__ = 'INSTANCE'
    __bind_key__  = 'XORCISM'

    InstanceID = Column(Integer, primary_key=True)
    ProcessID = Column(Integer)

    def __repr__(self):
        return f'<INSTANCE {self.InstanceID}>'

class INSTRUCTION(Base):
    __tablename__ = 'INSTRUCTION'
    __bind_key__  = 'XORCISM'

    InstructionID = Column(Integer, primary_key=True)
    OpcodeID = Column(Integer, nullable=False)
    Register1ID = Column(Integer)
    Register2ID = Column(Integer)
    InstructionOperand1Value = Column(Text)
    InstructionOperand2Value = Column(Text)
    InstructionHEXValue = Column(Text)

    def __repr__(self):
        return f'<INSTRUCTION {self.InstructionID}>'

class INTEGRITYLEVEL(Base):
    __tablename__ = 'INTEGRITYLEVEL'
    __bind_key__  = 'XORCISM'

    IntegrityLevelID = Column(Integer, primary_key=True)
    IntegrityLevel = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    IntegrityLevelDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<INTEGRITYLEVEL {self.IntegrityLevelID}>'

class INTEGRITYVIOLATIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'INTEGRITYVIOLATIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    IntegrityViolationStrategicObjectiveID = Column(Integer, primary_key=True)
    IntegrityViolationStrategicObjectiveName = Column(Text)
    IntegrityViolationStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INTEGRITYVIOLATIONSTRATEGICOBJECTIVE {self.IntegrityViolationStrategicObjectiveID}>'

class INTEGRITYVIOLATIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'INTEGRITYVIOLATIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    IntegrityViolationTacticalObjectiveID = Column(Integer, primary_key=True)
    IntegrityViolationTacticalObjectiveName = Column(Text)
    IntegrityViolationTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<INTEGRITYVIOLATIONTACTICALOBJECTIVE {self.IntegrityViolationTacticalObjectiveID}>'

class INTERACTIONLEVEL(Base):
    __tablename__ = 'INTERACTIONLEVEL'
    __bind_key__  = 'XORCISM'

    InteractionLevelID = Column(Integer, primary_key=True)
    InteractionLevel = Column(Text, nullable=False)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INTERACTIONLEVEL {self.InteractionLevelID}>'

class INTERACTIONPOINTS(Base):
    __tablename__ = 'INTERACTIONPOINTS'
    __bind_key__  = 'XORCISM'

    InteractionPointsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<INTERACTIONPOINTS {self.InteractionPointsID}>'

class INTERACTIONPOINTSECURITYCONTROL(Base):
    __tablename__ = 'INTERACTIONPOINTSECURITYCONTROL'
    __bind_key__  = 'XORCISM'

    InteractionPointSecurityControlID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<INTERACTIONPOINTSECURITYCONTROL {self.InteractionPointSecurityControlID}>'

class INTERFACE(Base):
    __tablename__ = 'INTERFACE'
    __bind_key__  = 'XORCISM'

    InterfaceID = Column(Integer, primary_key=True)
    InterfaceName = Column(Text, nullable=False)
    ipaddressIPv4 = Column(Text)
    ipaddressIPv6 = Column(Text)
    MacAddress = Column(Text)

    def __repr__(self):
        return f'<INTERFACE {self.InterfaceID}>'

class INTERFACEFORSYSTEMINFO(Base):
    __tablename__ = 'INTERFACEFORSYSTEMINFO'
    __bind_key__  = 'XORCISM'

    SystemInfoID = Column(Integer, primary_key=True)
    InterfaceID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INTERFACEFORSYSTEMINFO {self.SystemInfoID}>'

class INTRUSION(Base):
    __tablename__ = 'INTRUSION'
    __bind_key__  = 'XORCISM'

    IntrusionID = Column(Integer, primary_key=True)
    BreachID = Column(Integer)

    def __repr__(self):
        return f'<INTRUSION {self.IntrusionID}>'

class INVESTIGATION(Base):
    __tablename__ = 'INVESTIGATION'
    __bind_key__  = 'XORCISM'

    InvestigationID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer)

    def __repr__(self):
        return f'<INVESTIGATION {self.InvestigationID}>'

class IPCACTIONNAME(Base):
    __tablename__ = 'IPCACTIONNAME'
    __bind_key__  = 'XORCISM'

    IPCActionNameID = Column(Integer, primary_key=True)
    IPCActionNameName = Column(Text, nullable=False)
    IPCActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<IPCACTIONNAME {self.IPCActionNameID}>'

class IPFIXDATASET(Base):
    __tablename__ = 'IPFIXDATASET'
    __bind_key__  = 'XORCISM'

    IPFIXDataSetID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<IPFIXDATASET {self.IPFIXDataSetID}>'

class IPFIXMESSAGE(Base):
    __tablename__ = 'IPFIXMESSAGE'
    __bind_key__  = 'XORCISM'

    IPFIXMessageID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<IPFIXMESSAGE {self.IPFIXMessageID}>'

class IPFIXMESSAGEHEADER(Base):
    __tablename__ = 'IPFIXMESSAGEHEADER'
    __bind_key__  = 'XORCISM'

    IPFIXMessageHeaderID = Column(Integer, primary_key=True)
    VersionNumber = Column(Text)
    Byte_Length = Column(Integer)
    Export_Timestamp = Column(Integer)
    Sequence_Number = Column(Integer)
    Observation_Domain_ID = Column(Integer)

    def __repr__(self):
        return f'<IPFIXMESSAGEHEADER {self.IPFIXMessageHeaderID}>'

class IPFIXOPTIONSTEMPLATERECORD(Base):
    __tablename__ = 'IPFIXOPTIONSTEMPLATERECORD'
    __bind_key__  = 'XORCISM'

    IPFIXOptionsTemplateRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<IPFIXOPTIONSTEMPLATERECORD {self.IPFIXOptionsTemplateRecordID}>'

class IPFIXOPTIONSTEMPLATERECORDFIELDSPECIFIERS(Base):
    __tablename__ = 'IPFIXOPTIONSTEMPLATERECORDFIELDSPECIFIERS'
    __bind_key__  = 'XORCISM'

    IPFIXOptionsTemplateRecordFieldSpecifiersID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<IPFIXOPTIONSTEMPLATERECORDFIELDSPECIFIERS {self.IPFIXOptionsTemplateRecordFieldSpecifiersID}>'

class IPFIXOPTIONSTEMPLATERECORDHEADER(Base):
    __tablename__ = 'IPFIXOPTIONSTEMPLATERECORDHEADER'
    __bind_key__  = 'XORCISM'

    IPFIXOptionsTemplateRecordHeaderID = Column(Integer, primary_key=True)
    Template_ID = Column(Integer)
    Field_Count = Column(Integer)
    Scope_Field_Count = Column(Integer)

    def __repr__(self):
        return f'<IPFIXOPTIONSTEMPLATERECORDHEADER {self.IPFIXOptionsTemplateRecordHeaderID}>'

class IPFIXOPTIONSTEMPLATESET(Base):
    __tablename__ = 'IPFIXOPTIONSTEMPLATESET'
    __bind_key__  = 'XORCISM'

    IPFIXOptionsTemplateSetID = Column(Integer, primary_key=True)
    Padding = Column(Text)

    def __repr__(self):
        return f'<IPFIXOPTIONSTEMPLATESET {self.IPFIXOptionsTemplateSetID}>'

class IPFIXSET(Base):
    __tablename__ = 'IPFIXSET'
    __bind_key__  = 'XORCISM'

    IPFIXSetID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<IPFIXSET {self.IPFIXSetID}>'

class IPFIXSETHEADER(Base):
    __tablename__ = 'IPFIXSETHEADER'
    __bind_key__  = 'XORCISM'

    IPFIXSetHeaderID = Column(Integer, primary_key=True)
    Set_ID = Column(Integer)
    Length = Column(Integer)

    def __repr__(self):
        return f'<IPFIXSETHEADER {self.IPFIXSetHeaderID}>'

class IPFIXTEMPLATERECORD(Base):
    __tablename__ = 'IPFIXTEMPLATERECORD'
    __bind_key__  = 'XORCISM'

    IPFIXTemplateRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<IPFIXTEMPLATERECORD {self.IPFIXTemplateRecordID}>'

class IPFIXTEMPLATERECORDFIELDSPECIFIER(Base):
    __tablename__ = 'IPFIXTEMPLATERECORDFIELDSPECIFIER'
    __bind_key__  = 'XORCISM'

    IPFIXTemplateRecordFieldSpecifierID = Column(Integer, primary_key=True)
    Enterprise_Bit = Column(Integer)
    Information_Element_ID = Column(Text)
    Field_Length = Column(Integer)
    Enterprise_Number = Column(Text)

    def __repr__(self):
        return f'<IPFIXTEMPLATERECORDFIELDSPECIFIER {self.IPFIXTemplateRecordFieldSpecifierID}>'

class IPFIXTEMPLATERECORDHEADER(Base):
    __tablename__ = 'IPFIXTEMPLATERECORDHEADER'
    __bind_key__  = 'XORCISM'

    IPFIXTemplateRecordHeaderID = Column(Integer, primary_key=True)
    Template_ID = Column(Integer)
    Field_Count = Column(Text)

    def __repr__(self):
        return f'<IPFIXTEMPLATERECORDHEADER {self.IPFIXTemplateRecordHeaderID}>'

class IPFIXTEMPLATESET(Base):
    __tablename__ = 'IPFIXTEMPLATESET'
    __bind_key__  = 'XORCISM'

    IPFIXTemplateSetID = Column(Integer, primary_key=True)
    Padding = Column(Text)

    def __repr__(self):
        return f'<IPFIXTEMPLATESET {self.IPFIXTemplateSetID}>'

class IRCACTIONNAME(Base):
    __tablename__ = 'IRCACTIONNAME'
    __bind_key__  = 'XORCISM'

    IRCActionNameID = Column(Integer, primary_key=True)
    IRCActionNameName = Column(Text, nullable=False)
    IRCActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<IRCACTIONNAME {self.IRCActionNameID}>'

class ISHOWMESSAGEACTION(Base):
    __tablename__ = 'ISHOWMESSAGEACTION'
    __bind_key__  = 'XORCISM'

    IShowMessageActionID = Column(Integer, primary_key=True)
    Show_Message_Body = Column(Text)
    Show_Message_Title = Column(Text)

    def __repr__(self):
        return f'<ISHOWMESSAGEACTION {self.IShowMessageActionID}>'

class ISOCURRENCY(Base):
    __tablename__ = 'ISOCURRENCY'
    __bind_key__  = 'XORCISM'

    iso_currency_code = Column(Text, primary_key=True)

    def __repr__(self):
        return f'<ISOCURRENCY {self.iso_currency_code}>'

class JOB(Base):
    __tablename__ = 'JOB'
    __bind_key__  = 'XORCISM'

    JobID = Column(Integer, primary_key=True)
    JobGUID = Column(Text)
    CreatedDate = Column(Text)
    ProviderID = Column(Integer)
    DateStart = Column(Text)
    DateEnd = Column(Text)
    Status = Column(Text)
    AgentID = Column(Integer)
    SessionID = Column(Integer)
    AssetSessionID = Column(Integer)
    Parameters = Column(LargeBinary)
    XmlResult = Column(LargeBinary)
    ErrorReason = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<JOB {self.JobID}>'

class KERNELHOOK(Base):
    __tablename__ = 'KERNELHOOK'
    __bind_key__  = 'XORCISM'

    KernelHookID = Column(Integer, primary_key=True)
    KernelHookTypeEnumID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<KERNELHOOK {self.KernelHookID}>'

class KERNELHOOKTYPEENUM(Base):
    __tablename__ = 'KERNELHOOKTYPEENUM'
    __bind_key__  = 'XORCISM'

    KernelHookTypeEnumID = Column(Integer, primary_key=True)
    KernelHookType = Column(Text)
    KernelHookTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<KERNELHOOKTYPEENUM {self.KernelHookTypeEnumID}>'

class KEYWORD(Base):
    __tablename__ = 'KEYWORD'
    __bind_key__  = 'XORCISM'

    KeywordID = Column(Integer, primary_key=True)
    KeywordValue = Column(Text, nullable=False)
    lang = Column(Text)

    def __repr__(self):
        return f'<KEYWORD {self.KeywordID}>'

class KILLCHAIN(Base):
    __tablename__ = 'KILLCHAIN'
    __bind_key__  = 'XORCISM'

    KillChainID = Column(Integer, primary_key=True)
    KillChainGID = Column(Text)
    KillChainName = Column(Text)
    KillChainDefiner = Column(Text)
    KillChainReference = Column(Text)
    KillChainNumberOfPhases = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<KILLCHAIN {self.KillChainID}>'

class KILLCHAINFORTHREATACTORTTP(Base):
    __tablename__ = 'KILLCHAINFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    KillChainID = Column(Integer, primary_key=True)
    ThreatActorTTPID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<KILLCHAINFORTHREATACTORTTP {self.KillChainID}>'

class KILLCHAINPHASE(Base):
    __tablename__ = 'KILLCHAINPHASE'
    __bind_key__  = 'XORCISM'

    KillChainPhaseID = Column(Integer, primary_key=True)
    KillChainPhaseGID = Column(Text)
    KillChainPhaseName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<KILLCHAINPHASE {self.KillChainPhaseID}>'

class KILLCHAINPHASEFORKILLCHAIN(Base):
    __tablename__ = 'KILLCHAINPHASEFORKILLCHAIN'
    __bind_key__  = 'XORCISM'

    KillChainKillChainPhaseID = Column(Integer, primary_key=True)
    KillChainID = Column(Integer, nullable=False)
    KillChainPhaseID = Column(Integer, nullable=False)
    ordinality = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<KILLCHAINPHASEFORKILLCHAIN {self.KillChainKillChainPhaseID}>'

class KILLCHAINPHASEFORTHREATACTORTTP(Base):
    __tablename__ = 'KILLCHAINPHASEFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    ThreatActorTTPKillChainPhaseID = Column(Integer, primary_key=True)
    KillChainPhaseID = Column(Integer, nullable=False)
    ThreatActorTTPID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<KILLCHAINPHASEFORTHREATACTORTTP {self.ThreatActorTTPKillChainPhaseID}>'

class LABEL(Base):
    __tablename__ = 'LABEL'
    __bind_key__  = 'XORCISM'

    LabelID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LABEL {self.LabelID}>'

class LANGUAGE(Base):
    __tablename__ = 'LANGUAGE'
    __bind_key__  = 'XORCISM'

    LanguageID = Column(Integer, primary_key=True)
    LanguageGUID = Column(Text)
    LanguageName = Column(Text)
    LanguageDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LANGUAGE {self.LanguageID}>'

class LANGUAGECHARACTEREOL(Base):
    __tablename__ = 'LANGUAGECHARACTEREOL'
    __bind_key__  = 'XORCISM'

    LanguageCharacterEOLID = Column(Integer, primary_key=True)
    LanguageID = Column(Integer, nullable=False)
    CharacterID = Column(Integer, nullable=False)
    ordinal_position = Column(Integer)

    def __repr__(self):
        return f'<LANGUAGECHARACTEREOL {self.LanguageCharacterEOLID}>'

class LANGUAGECLASS(Base):
    __tablename__ = 'LANGUAGECLASS'
    __bind_key__  = 'XORCISM'

    LanguageClassID = Column(Integer, primary_key=True)
    LanguageClassDescription = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LANGUAGECLASS {self.LanguageClassID}>'

class LANGUAGEFORAPPLICATION(Base):
    __tablename__ = 'LANGUAGEFORAPPLICATION'
    __bind_key__  = 'XORCISM'

    ApplicationLanguageID = Column(Integer, primary_key=True)
    ApplicationID = Column(Integer, nullable=False)
    LanguageID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LANGUAGEFORAPPLICATION {self.ApplicationLanguageID}>'

class LANGUAGEFORTECHNICALCONTEXT(Base):
    __tablename__ = 'LANGUAGEFORTECHNICALCONTEXT'
    __bind_key__  = 'XORCISM'

    TechnicalContextLanguageID = Column(Integer, primary_key=True)
    LanguageID = Column(Integer, nullable=False)
    LanguageGUID = Column(Text)
    TechnicalContextID = Column(Integer, nullable=False)
    TechnicalContextGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LANGUAGEFORTECHNICALCONTEXT {self.TechnicalContextLanguageID}>'

class LANGUAGEFUNCTION(Base):
    __tablename__ = 'LANGUAGEFUNCTION'
    __bind_key__  = 'XORCISM'

    LanguageFunctionID = Column(Integer, primary_key=True)
    LanguageFunctionGUID = Column(Text)
    LanguageID = Column(Integer, nullable=False)
    LanguageGUID = Column(Text)
    FunctionID = Column(Integer, nullable=False)
    FunctionGUID = Column(Text)
    LanguageFunctionDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isDeprecated = Column(Integer)
    CreationObjectID = Column(Integer)
    CreationObjectGUID = Column(Text)
    isKnownVulnerable = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionMethodGUID = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceLevelGUID = Column(Text)
    ConfidenceReasonID = Column(Integer)
    ConfidenceReasonGUID = Column(Text)
    TrustLevelID = Column(Integer)
    TrustLevelGUID = Column(Text)
    TrustReasonID = Column(Integer)
    TrustReasonGUID = Column(Text)
    VocabularyID = Column(Integer)
    VocabularyGUID = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LANGUAGEFUNCTION {self.LanguageFunctionID}>'

class LANGUAGEFUNCTIONREFERENCE(Base):
    __tablename__ = 'LANGUAGEFUNCTIONREFERENCE'
    __bind_key__  = 'XORCISM'

    LanguageFunctionReferenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LANGUAGEFUNCTIONREFERENCE {self.LanguageFunctionReferenceID}>'

class LANGUAGEFUNCTIONTAG(Base):
    __tablename__ = 'LANGUAGEFUNCTIONTAG'
    __bind_key__  = 'XORCISM'

    LanguageFunctionTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LANGUAGEFUNCTIONTAG {self.LanguageFunctionTagID}>'

class LAW(Base):
    __tablename__ = 'LAW'
    __bind_key__  = 'XORCISM'

    LawID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LAW {self.LawID}>'

class LIBRARY(Base):
    __tablename__ = 'LIBRARY'
    __bind_key__  = 'XORCISM'

    LibraryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LIBRARY {self.LibraryID}>'

class LIBRARYACTIONNAME(Base):
    __tablename__ = 'LIBRARYACTIONNAME'
    __bind_key__  = 'XORCISM'

    LibraryActionNameID = Column(Integer, primary_key=True)
    LibraryActionNameName = Column(Text, nullable=False)
    LibraryActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<LIBRARYACTIONNAME {self.LibraryActionNameID}>'

class LIBRARYDESCRIPTION(Base):
    __tablename__ = 'LIBRARYDESCRIPTION'
    __bind_key__  = 'XORCISM'

    LibraryDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LIBRARYDESCRIPTION {self.LibraryDescriptionID}>'

class LIBRARYREFERENCE(Base):
    __tablename__ = 'LIBRARYREFERENCE'
    __bind_key__  = 'XORCISM'

    LibraryReferenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LIBRARYREFERENCE {self.LibraryReferenceID}>'

class LIBRARYTAG(Base):
    __tablename__ = 'LIBRARYTAG'
    __bind_key__  = 'XORCISM'

    LibraryTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LIBRARYTAG {self.LibraryTagID}>'

class LICENSE(Base):
    __tablename__ = 'LICENSE'
    __bind_key__  = 'XORCISM'

    LicenseID = Column(Integer, primary_key=True)
    LicenseName = Column(Text)
    LicenseVersion = Column(Text)
    LicenseTypeID = Column(Integer)
    LicenseDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LICENSE {self.LicenseID}>'

class LICENSEACCESSRECORD(Base):
    __tablename__ = 'LICENSEACCESSRECORD'
    __bind_key__  = 'XORCISM'

    LicenseAccessRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LICENSEACCESSRECORD {self.LicenseAccessRecordID}>'

class LICENSECHANGERECORD(Base):
    __tablename__ = 'LICENSECHANGERECORD'
    __bind_key__  = 'XORCISM'

    LicenseChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LICENSECHANGERECORD {self.LicenseChangeRecordID}>'

class LICENSERESTRICTION(Base):
    __tablename__ = 'LICENSERESTRICTION'
    __bind_key__  = 'XORCISM'

    LicenseRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LICENSERESTRICTION {self.LicenseRestrictionID}>'

class LICENSETYPE(Base):
    __tablename__ = 'LICENSETYPE'
    __bind_key__  = 'XORCISM'

    LicenseTypeID = Column(Integer, primary_key=True)
    LicenseTypeName = Column(Text)
    LicenseTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<LICENSETYPE {self.LicenseTypeID}>'

class LINK(Base):
    __tablename__ = 'LINK'
    __bind_key__  = 'XORCISM'

    LinkID = Column(Integer, primary_key=True)
    LinkGUID = Column(Text)
    ReferenceID = Column(Integer)
    LinkURL = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<LINK {self.LinkID}>'

class LINKTYPE(Base):
    __tablename__ = 'LINKTYPE'
    __bind_key__  = 'XORCISM'

    LinkTypeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LINKTYPE {self.LinkTypeID}>'

class LINUXPACKAGE(Base):
    __tablename__ = 'LINUXPACKAGE'
    __bind_key__  = 'XORCISM'

    LinuxPackageID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LINUXPACKAGE {self.LinuxPackageID}>'

class LOCALE(Base):
    __tablename__ = 'LOCALE'
    __bind_key__  = 'XORCISM'

    LocaleID = Column(Integer, primary_key=True)
    LocaleGUID = Column(Text)
    LCIDHex = Column(Text)
    LCIDDec = Column(Integer)
    LocaleValue = Column(Text)
    LocaleDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LOCALE {self.LocaleID}>'

class LOCALEDESCRIPTION(Base):
    __tablename__ = 'LOCALEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    LocaleDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LOCALEDESCRIPTION {self.LocaleDescriptionID}>'

class LOCALEREFERENCE(Base):
    __tablename__ = 'LOCALEREFERENCE'
    __bind_key__  = 'XORCISM'

    LocaleReferenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LOCALEREFERENCE {self.LocaleReferenceID}>'

class LOCATIONPOINT(Base):
    __tablename__ = 'LOCATIONPOINT'
    __bind_key__  = 'XORCISM'

    LocationPointID = Column(Integer, primary_key=True)
    latitude = Column(Integer, nullable=False)
    longitude = Column(Integer, nullable=False)
    elevation = Column(Integer)
    radius = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LOCATIONPOINT {self.LocationPointID}>'

class LOCATIONPOINTFORASSET(Base):
    __tablename__ = 'LOCATIONPOINTFORASSET'
    __bind_key__  = 'XORCISM'

    LocationPointID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    source = Column(Text)

    def __repr__(self):
        return f'<LOCATIONPOINTFORASSET {self.LocationPointID}>'

class LOCATIONPOINTFORORGANISATION(Base):
    __tablename__ = 'LOCATIONPOINTFORORGANISATION'
    __bind_key__  = 'XORCISM'

    LocationPointID = Column(Integer, primary_key=True)
    OrganisationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    source = Column(Text)

    def __repr__(self):
        return f'<LOCATIONPOINTFORORGANISATION {self.LocationPointID}>'

class LOCATIONPOINTFORPERSON(Base):
    __tablename__ = 'LOCATIONPOINTFORPERSON'
    __bind_key__  = 'XORCISM'

    LocationPointID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    source = Column(Text)

    def __repr__(self):
        return f'<LOCATIONPOINTFORPERSON {self.LocationPointID}>'

class LOCATIONREGION(Base):
    __tablename__ = 'LOCATIONREGION'
    __bind_key__  = 'XORCISM'

    LocationRegionID = Column(Integer, primary_key=True)
    regionname = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<LOCATIONREGION {self.LocationRegionID}>'

class LOCATIONREGIONFORASSET(Base):
    __tablename__ = 'LOCATIONREGIONFORASSET'
    __bind_key__  = 'XORCISM'

    LocationRegionID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    BLOB = Column(Text, nullable=False)
    source = Column(Text)

    def __repr__(self):
        return f'<LOCATIONREGIONFORASSET {self.LocationRegionID}>'

class LOGFILE(Base):
    __tablename__ = 'LOGFILE'
    __bind_key__  = 'XORCISM'

    LogFileID = Column(Integer, primary_key=True)
    FileID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<LOGFILE {self.LogFileID}>'

class LOSSDURATION(Base):
    __tablename__ = 'LOSSDURATION'
    __bind_key__  = 'XORCISM'

    LossDurationID = Column(Integer, primary_key=True)
    LossDurationName = Column(Text)
    LossDurationDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<LOSSDURATION {self.LossDurationID}>'

class LOSSFACTOR(Base):
    __tablename__ = 'LOSSFACTOR'
    __bind_key__  = 'XORCISM'

    LossFactorID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<LOSSFACTOR {self.LossFactorID}>'

class LOSSFORM(Base):
    __tablename__ = 'LOSSFORM'
    __bind_key__  = 'XORCISM'

    LossFormID = Column(Integer, primary_key=True)
    LossFormName = Column(Text, nullable=False)
    LossFormDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<LOSSFORM {self.LossFormID}>'

class LOSSPROPERTY(Base):
    __tablename__ = 'LOSSPROPERTY'
    __bind_key__  = 'XORCISM'

    LossPropertyID = Column(Integer, primary_key=True)
    LossPropertyGUID = Column(Text)
    LossPropertyName = Column(Text, nullable=False)
    LossPropertyDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<LOSSPROPERTY {self.LossPropertyID}>'

class LOSSPROPERTYFORINCIDENT(Base):
    __tablename__ = 'LOSSPROPERTYFORINCIDENT'
    __bind_key__  = 'XORCISM'

    IncidentID = Column(Integer, primary_key=True)
    LossPropertyID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<LOSSPROPERTYFORINCIDENT {self.IncidentID}>'

class MACHINEACCESSCONTROLPROPERTIES(Base):
    __tablename__ = 'MACHINEACCESSCONTROLPROPERTIES'
    __bind_key__  = 'XORCISM'

    MachineAccessControlPropertiesID = Column(Integer, primary_key=True)
    MachineAccessControlPropertiesName = Column(Text)
    MachineAccessControlPropertiesDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MACHINEACCESSCONTROLPROPERTIES {self.MachineAccessControlPropertiesID}>'

class MACHINEACCESSCONTROLSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'MACHINEACCESSCONTROLSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    MachineAccessControlStrategicObjectiveID = Column(Integer, primary_key=True)
    MachineAccessControlStrategicObjectiveName = Column(Text)
    MachineAccessControlStrategicObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<MACHINEACCESSCONTROLSTRATEGICOBJECTIVE {self.MachineAccessControlStrategicObjectiveID}>'

class MACHINEACCESSCONTROLTACTICALOBJECTIVE(Base):
    __tablename__ = 'MACHINEACCESSCONTROLTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    MachineAccessControlTacticalObjectiveID = Column(Integer, primary_key=True)
    MachineAccessControlTacticalObjectiveName = Column(Text)
    MachineAccessControlTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<MACHINEACCESSCONTROLTACTICALOBJECTIVE {self.MachineAccessControlTacticalObjectiveID}>'

class MAINTENANCENOTE(Base):
    __tablename__ = 'MAINTENANCENOTE'
    __bind_key__  = 'XORCISM'

    MaintenanceNoteID = Column(Integer, primary_key=True)
    MaintenanceNoteText = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<MAINTENANCENOTE {self.MaintenanceNoteID}>'

class MANAGEMENT(Base):
    __tablename__ = 'MANAGEMENT'
    __bind_key__  = 'XORCISM'

    ManagementID = Column(Integer, primary_key=True)
    ManagementName = Column(Text)
    ManagementDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<MANAGEMENT {self.ManagementID}>'

class MATURITYLEVEL(Base):
    __tablename__ = 'MATURITYLEVEL'
    __bind_key__  = 'XORCISM'

    MaturityLevelID = Column(Integer, primary_key=True)
    MaturityLevelGUID = Column(Text)
    MaturityLevelVocabularyID = Column(Text)
    MaturityLevelName = Column(Text)
    MaturityLevelDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MATURITYLEVEL {self.MaturityLevelID}>'

class MATURITYRATING(Base):
    __tablename__ = 'MATURITYRATING'
    __bind_key__  = 'XORCISM'

    MaturityRatingID = Column(Integer, primary_key=True)
    ScoringSystemID = Column(Integer)

    def __repr__(self):
        return f'<MATURITYRATING {self.MaturityRatingID}>'

class MEASURESOURCE(Base):
    __tablename__ = 'MEASURESOURCE'
    __bind_key__  = 'XORCISM'

    MeasureSourceID = Column(Integer, primary_key=True)
    SourceClassID = Column(Integer)
    SourceClassName = Column(Text)
    MeasureSourceName = Column(Text)
    SourceTypeID = Column(Integer)
    SourceTypeName = Column(Text)
    MeasureSourceDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<MEASURESOURCE {self.MeasureSourceID}>'

class MEASURESOURCECONTRIBUTOR(Base):
    __tablename__ = 'MEASURESOURCECONTRIBUTOR'
    __bind_key__  = 'XORCISM'

    MeasureSourceID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<MEASURESOURCECONTRIBUTOR {self.MeasureSourceID}>'

class MEASURESOURCEINFORMATIONSOURCETYPE(Base):
    __tablename__ = 'MEASURESOURCEINFORMATIONSOURCETYPE'
    __bind_key__  = 'XORCISM'

    MeasureSourceID = Column(Integer, primary_key=True)
    InformationSourceTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<MEASURESOURCEINFORMATIONSOURCETYPE {self.MeasureSourceID}>'

class MEASURESOURCEPLATFORM(Base):
    __tablename__ = 'MEASURESOURCEPLATFORM'
    __bind_key__  = 'XORCISM'

    MeasureSourceID = Column(Integer, primary_key=True)
    PlatformID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<MEASURESOURCEPLATFORM {self.MeasureSourceID}>'

class MEASURESOURCESYSTEM(Base):
    __tablename__ = 'MEASURESOURCESYSTEM'
    __bind_key__  = 'XORCISM'

    MeasureSourceID = Column(Integer, primary_key=True)
    SystemID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<MEASURESOURCESYSTEM {self.MeasureSourceID}>'

class MEASURESOURCETOOL(Base):
    __tablename__ = 'MEASURESOURCETOOL'
    __bind_key__  = 'XORCISM'

    MeasureSourceID = Column(Integer, primary_key=True)
    ToolInformationID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<MEASURESOURCETOOL {self.MeasureSourceID}>'

class MEASURESOURCETOOLTYPE(Base):
    __tablename__ = 'MEASURESOURCETOOLTYPE'
    __bind_key__  = 'XORCISM'

    MeasureSourceID = Column(Integer, primary_key=True)
    ToolTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<MEASURESOURCETOOLTYPE {self.MeasureSourceID}>'

class MECHANISM(Base):
    __tablename__ = 'MECHANISM'
    __bind_key__  = 'XORCISM'

    MechanismID = Column(Integer, primary_key=True)
    MechanismGUID = Column(Text)
    MechanismName = Column(Text)
    MechanismDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MECHANISM {self.MechanismID}>'

class MECHANISMDESCRIPTION(Base):
    __tablename__ = 'MECHANISMDESCRIPTION'
    __bind_key__  = 'XORCISM'

    MechanismDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MECHANISMDESCRIPTION {self.MechanismDescriptionID}>'

class MECHANISMREFERENCE(Base):
    __tablename__ = 'MECHANISMREFERENCE'
    __bind_key__  = 'XORCISM'

    MechanismReferenceID = Column(Integer, primary_key=True)
    MechanismReferenceGUID = Column(Text)
    MechanismID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<MECHANISMREFERENCE {self.MechanismReferenceID}>'

class MECHANISMRELATIONSHIP(Base):
    __tablename__ = 'MECHANISMRELATIONSHIP'
    __bind_key__  = 'XORCISM'

    MechanismRelationshipID = Column(Integer, primary_key=True)
    MechanismRelationshipGUID = Column(Text)
    MechanismParentID = Column(Integer, nullable=False)
    MechanismSubjectID = Column(Integer, nullable=False)
    MechanismRelationshipDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<MECHANISMRELATIONSHIP {self.MechanismRelationshipID}>'

class MECHANISMTAG(Base):
    __tablename__ = 'MECHANISMTAG'
    __bind_key__  = 'XORCISM'

    MechanismTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MECHANISMTAG {self.MechanismTagID}>'

class MEMORYADDRESS(Base):
    __tablename__ = 'MEMORYADDRESS'
    __bind_key__  = 'XORCISM'

    MemoryAddressID = Column(Integer, primary_key=True)
    MemoryAddressGUID = Column(Text)
    MemoryAddressValue = Column(Text, nullable=False)
    MemoryAddressDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<MEMORYADDRESS {self.MemoryAddressID}>'

class MEMORYADDRESSREFERENCE(Base):
    __tablename__ = 'MEMORYADDRESSREFERENCE'
    __bind_key__  = 'XORCISM'

    MemoryAddressReferenceID = Column(Integer, primary_key=True)
    MemoryAddressID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<MEMORYADDRESSREFERENCE {self.MemoryAddressReferenceID}>'

class MEMORYDUMP(Base):
    __tablename__ = 'MEMORYDUMP'
    __bind_key__  = 'XORCISM'

    MemoryDumpID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MEMORYDUMP {self.MemoryDumpID}>'

class MEMORYOBJECT(Base):
    __tablename__ = 'MEMORYOBJECT'
    __bind_key__  = 'XORCISM'

    MemoryObjectID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MEMORYOBJECT {self.MemoryObjectID}>'

class MEMORYSECTIONLIST(Base):
    __tablename__ = 'MEMORYSECTIONLIST'
    __bind_key__  = 'XORCISM'

    MemorySectionListID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MEMORYSECTIONLIST {self.MemorySectionListID}>'

class MESSAGE(Base):
    __tablename__ = 'MESSAGE'
    __bind_key__  = 'XORCISM'

    MessageID = Column(Integer, primary_key=True)
    MessageGUID = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<MESSAGE {self.MessageID}>'

class MESSAGECONFIDENTIALITYLEVEL(Base):
    __tablename__ = 'MESSAGECONFIDENTIALITYLEVEL'
    __bind_key__  = 'XORCISM'

    MessageConfidentialityLevelID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MESSAGECONFIDENTIALITYLEVEL {self.MessageConfidentialityLevelID}>'

class MESSAGELEVEL(Base):
    __tablename__ = 'MESSAGELEVEL'
    __bind_key__  = 'XORCISM'

    MessageLevelID = Column(Integer, primary_key=True)
    MessageLevelValue = Column(Text, nullable=False)
    MessageLevelDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<MESSAGELEVEL {self.MessageLevelID}>'

class MESSAGESMS(Base):
    __tablename__ = 'MESSAGESMS'
    __bind_key__  = 'XORCISM'

    MessageSMSID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MESSAGESMS {self.MessageSMSID}>'

class METADATA(Base):
    __tablename__ = 'METADATA'
    __bind_key__  = 'XORCISM'

    MetadataID = Column(Integer, primary_key=True)
    MetadataContent = Column(Text, nullable=False)
    type = Column(Text)

    def __repr__(self):
        return f'<METADATA {self.MetadataID}>'

class METHOD(Base):
    __tablename__ = 'METHOD'
    __bind_key__  = 'XORCISM'

    MethodID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<METHOD {self.MethodID}>'

class METHODOLOGY(Base):
    __tablename__ = 'METHODOLOGY'
    __bind_key__  = 'XORCISM'

    MethodologyID = Column(Integer, primary_key=True)
    MethodologyGUID = Column(Text)
    MethodologyName = Column(Text, nullable=False)
    MethodologyDescription = Column(Text)
    isEncrypted = Column(Integer)
    lang = Column(Text)
    VocabularyID = Column(Integer)
    MethodologyReference = Column(Text)
    MethodologyVersion = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<METHODOLOGY {self.MethodologyID}>'

class METHODOLOGYCHAPTER(Base):
    __tablename__ = 'METHODOLOGYCHAPTER'
    __bind_key__  = 'XORCISM'

    MethodologyChapterID = Column(Integer, primary_key=True)
    ChapterID = Column(Integer)

    def __repr__(self):
        return f'<METHODOLOGYCHAPTER {self.MethodologyChapterID}>'

class METHODOLOGYDESCRIPTION(Base):
    __tablename__ = 'METHODOLOGYDESCRIPTION'
    __bind_key__  = 'XORCISM'

    MethodologyDescriptionID = Column(Integer, primary_key=True)
    MethodologyID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<METHODOLOGYDESCRIPTION {self.MethodologyDescriptionID}>'

class METHODOLOGYNODE(Base):
    __tablename__ = 'METHODOLOGYNODE'
    __bind_key__  = 'XORCISM'

    MethodologyNodeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<METHODOLOGYNODE {self.MethodologyNodeID}>'

class METHODOLOGYREFERENCE(Base):
    __tablename__ = 'METHODOLOGYREFERENCE'
    __bind_key__  = 'XORCISM'

    MethodologyReferenceID = Column(Integer, primary_key=True)
    MethodologyID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<METHODOLOGYREFERENCE {self.MethodologyReferenceID}>'

class METHODOLOGYTAG(Base):
    __tablename__ = 'METHODOLOGYTAG'
    __bind_key__  = 'XORCISM'

    MethodologyTagID = Column(Integer, primary_key=True)
    MethodologyID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<METHODOLOGYTAG {self.MethodologyTagID}>'

class METHODOLOGYTECHNIQUE(Base):
    __tablename__ = 'METHODOLOGYTECHNIQUE'
    __bind_key__  = 'XORCISM'

    MethodologyTechniqueID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<METHODOLOGYTECHNIQUE {self.MethodologyTechniqueID}>'

class METHODOLOGYTEST(Base):
    __tablename__ = 'METHODOLOGYTEST'
    __bind_key__  = 'XORCISM'

    MethodologyTestID = Column(Integer, primary_key=True)
    MethodologyTestGUID = Column(Text)
    MethodologyID = Column(Integer)
    MethodologyGUID = Column(Text)
    TestID = Column(Integer)
    TestGUID = Column(Text)
    TestVocabularyID = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<METHODOLOGYTEST {self.MethodologyTestID}>'

class METRIC(Base):
    __tablename__ = 'METRIC'
    __bind_key__  = 'XORCISM'

    MetricID = Column(Integer, primary_key=True)
    MetricGUID = Column(Text)
    MetricName = Column(Text)
    MetricDescription = Column(Text)
    MetricExamples = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<METRIC {self.MetricID}>'

class METRICCATEGORY(Base):
    __tablename__ = 'METRICCATEGORY'
    __bind_key__  = 'XORCISM'

    MetricCategoryID = Column(Integer, primary_key=True)
    CategoryID = Column(Integer)

    def __repr__(self):
        return f'<METRICCATEGORY {self.MetricCategoryID}>'

class METRICCHANGERECORD(Base):
    __tablename__ = 'METRICCHANGERECORD'
    __bind_key__  = 'XORCISM'

    MetricChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<METRICCHANGERECORD {self.MetricChangeRecordID}>'

class METRICDESCRIPTION(Base):
    __tablename__ = 'METRICDESCRIPTION'
    __bind_key__  = 'XORCISM'

    MetricDescriptionID = Column(Integer, primary_key=True)
    MetricID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<METRICDESCRIPTION {self.MetricDescriptionID}>'

class METRICREFERENCE(Base):
    __tablename__ = 'METRICREFERENCE'
    __bind_key__  = 'XORCISM'

    MetricReferenceID = Column(Integer, primary_key=True)
    MetricID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<METRICREFERENCE {self.MetricReferenceID}>'

class METRICTAG(Base):
    __tablename__ = 'METRICTAG'
    __bind_key__  = 'XORCISM'

    MetricTagID = Column(Integer, primary_key=True)
    MetricID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<METRICTAG {self.MetricTagID}>'

class MIME(Base):
    __tablename__ = 'MIME'
    __bind_key__  = 'XORCISM'

    MIMEID = Column(Integer, primary_key=True)
    MIMEType = Column(Text)
    MIMETypeDescription = Column(Text)
    MIMEVersion = Column(Text)
    MIMETypeReference = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<MIME {self.MIMEID}>'

class MIMEVERSION(Base):
    __tablename__ = 'MIMEVERSION'
    __bind_key__  = 'XORCISM'

    MIMEVersionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MIMEVERSION {self.MIMEVersionID}>'

class MIMEWHITELIST(Base):
    __tablename__ = 'MIMEWHITELIST'
    __bind_key__  = 'XORCISM'

    MIMEWhitelistID = Column(Integer, primary_key=True)
    MIMEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<MIMEWHITELIST {self.MIMEWhitelistID}>'

class MININGSCHEMA(Base):
    __tablename__ = 'MININGSCHEMA'
    __bind_key__  = 'XORCISM'

    MiningSchemaID = Column(Integer, primary_key=True)
    SchemaID = Column(Integer)

    def __repr__(self):
        return f'<MININGSCHEMA {self.MiningSchemaID}>'

class MITIGATION(Base):
    __tablename__ = 'MITIGATION'
    __bind_key__  = 'XORCISM'

    MitigationID = Column(Integer, primary_key=True)
    MitigationGUID = Column(Text)
    MitigationVocabularyID = Column(Text)
    MitigationName = Column(Text)
    SolutionMitigationText = Column(Text, nullable=False)
    EffectivenessID = Column(Integer)
    Mitigation_Effectiveness_Notes = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ShortTerm = Column(Integer)
    LongTerm = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MITIGATION {self.MitigationID}>'

class MITIGATIONCODE(Base):
    __tablename__ = 'MITIGATIONCODE'
    __bind_key__  = 'XORCISM'

    MitigationCodeID = Column(Integer, primary_key=True)
    MitigationID = Column(Integer, nullable=False)
    CodeID = Column(Integer, nullable=False)
    Block_Nature = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<MITIGATIONCODE {self.MitigationCodeID}>'

class MITIGATIONEFFECTIVENESS(Base):
    __tablename__ = 'MITIGATIONEFFECTIVENESS'
    __bind_key__  = 'XORCISM'

    MitigationEffectivenessID = Column(Integer, primary_key=True)
    MitigationID = Column(Integer)
    EffectivenessID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<MITIGATIONEFFECTIVENESS {self.MitigationEffectivenessID}>'

class MITIGATIONFORATTACKPATTERN(Base):
    __tablename__ = 'MITIGATIONFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternMitigationID = Column(Integer, primary_key=True)
    MitigationID = Column(Integer, nullable=False)
    MitigationGUID = Column(Text)
    AttackPatternID = Column(Integer, nullable=False)
    AttackPatternGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MITIGATIONFORATTACKPATTERN {self.AttackPatternMitigationID}>'

class MITIGATIONFORCWE(Base):
    __tablename__ = 'MITIGATIONFORCWE'
    __bind_key__  = 'XORCISM'

    CWEMitigationID = Column(Integer, primary_key=True)
    MitigationID = Column(Integer, nullable=False)
    MitigationGUID = Column(Text)
    MitigationVocabularyID = Column(Text)
    CWEID = Column(Text, nullable=False)
    MitigationPhaseID = Column(Integer)
    MitigationStrategyID = Column(Integer)
    CWEMitigationDescription = Column(Text)
    EffectivenessID = Column(Integer)
    CWEMitigationEffectivenessNotes = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MITIGATIONFORCWE {self.CWEMitigationID}>'

class MITIGATIONPHASE(Base):
    __tablename__ = 'MITIGATIONPHASE'
    __bind_key__  = 'XORCISM'

    MitigationPhaseID = Column(Integer, primary_key=True)
    MitigationPhaseGUID = Column(Text)
    PhaseID = Column(Integer)
    PhaseGUID = Column(Text)
    MitigationPhaseName = Column(Text, nullable=False)
    MitigationPhaseDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ImportanceID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MITIGATIONPHASE {self.MitigationPhaseID}>'

class MITIGATIONPHASEFORMITIGATION(Base):
    __tablename__ = 'MITIGATIONPHASEFORMITIGATION'
    __bind_key__  = 'XORCISM'

    MitigationMitigationPhaseID = Column(Integer, primary_key=True)
    MitigationID = Column(Integer, nullable=False)
    MitigationGUID = Column(Text)
    MitigationPhaseID = Column(Integer, nullable=False)
    MitigationPhaseGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MITIGATIONPHASEFORMITIGATION {self.MitigationMitigationPhaseID}>'

class MITIGATIONPHASETAG(Base):
    __tablename__ = 'MITIGATIONPHASETAG'
    __bind_key__  = 'XORCISM'

    MitigationPhaseTagID = Column(Integer, primary_key=True)
    MitigationPhaseID = Column(Integer)
    MitigationPhaseGUID = Column(Text)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<MITIGATIONPHASETAG {self.MitigationPhaseTagID}>'

class MITIGATIONREFERENCE(Base):
    __tablename__ = 'MITIGATIONREFERENCE'
    __bind_key__  = 'XORCISM'

    MitigationReferenceID = Column(Integer, primary_key=True)
    MitigationID = Column(Integer, nullable=False)
    MitigationGUID = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    MitigationReferenceDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MITIGATIONREFERENCE {self.MitigationReferenceID}>'

class MITIGATIONSTRATEGY(Base):
    __tablename__ = 'MITIGATIONSTRATEGY'
    __bind_key__  = 'XORCISM'

    MitigationStrategyID = Column(Integer, primary_key=True)
    MitigationStrategyGUID = Column(Text)
    StrategyID = Column(Integer)
    StrategyGUID = Column(Text)
    MitigationStrategyName = Column(Text)
    MitigationStrategyDescription = Column(Text)
    MitigationStrategyVocabularyID = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MITIGATIONSTRATEGY {self.MitigationStrategyID}>'

class MITIGATIONSTRATEGYFORMITIGATION(Base):
    __tablename__ = 'MITIGATIONSTRATEGYFORMITIGATION'
    __bind_key__  = 'XORCISM'

    MitigationMitigationStrategyID = Column(Integer, primary_key=True)
    MitigationID = Column(Integer, nullable=False)
    MitigationGUID = Column(Text)
    MitigationStrategyID = Column(Integer, nullable=False)
    MitigationStrategyGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer, nullable=False)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MITIGATIONSTRATEGYFORMITIGATION {self.MitigationMitigationStrategyID}>'

class MITIGATIONSTRATEGYTAG(Base):
    __tablename__ = 'MITIGATIONSTRATEGYTAG'
    __bind_key__  = 'XORCISM'

    MitigationStrategyTagID = Column(Integer, primary_key=True)
    MitigationStrategyID = Column(Integer)
    MitigationStrategyGUID = Column(Text)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<MITIGATIONSTRATEGYTAG {self.MitigationStrategyTagID}>'

class MMSMESSAGE(Base):
    __tablename__ = 'MMSMESSAGE'
    __bind_key__  = 'XORCISM'

    MMSMessageID = Column(Integer, primary_key=True)
    MessageID = Column(Integer)
    SMSMessageID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MMSMESSAGE {self.MMSMessageID}>'

class MOBILEDEVICE(Base):
    __tablename__ = 'MOBILEDEVICE'
    __bind_key__  = 'XORCISM'

    MobileDeviceID = Column(Integer, primary_key=True)
    DeviceID = Column(Integer)

    def __repr__(self):
        return f'<MOBILEDEVICE {self.MobileDeviceID}>'

class MODEL(Base):
    __tablename__ = 'MODEL'
    __bind_key__  = 'XORCISM'

    ModelID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MODEL {self.ModelID}>'

class MODELCATEGORY(Base):
    __tablename__ = 'MODELCATEGORY'
    __bind_key__  = 'XORCISM'

    ModelCategoryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<MODELCATEGORY {self.ModelCategoryID}>'

class MODELDESCRIPTION(Base):
    __tablename__ = 'MODELDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ModelDescriptionID = Column(Integer, primary_key=True)
    ModelID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<MODELDESCRIPTION {self.ModelDescriptionID}>'

class MODULE(Base):
    __tablename__ = 'MODULE'
    __bind_key__  = 'XORCISM'

    ModuleID = Column(Integer, primary_key=True)
    ModuleName = Column(Text)
    ModuleDescription = Column(Text)
    ModuleVersion = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<MODULE {self.ModuleID}>'

class MUTEX(Base):
    __tablename__ = 'MUTEX'
    __bind_key__  = 'XORCISM'

    MutexID = Column(Integer, primary_key=True)
    MutexName = Column(Text)
    MutexDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<MUTEX {self.MutexID}>'

class MUTEXNAME(Base):
    __tablename__ = 'MUTEXNAME'
    __bind_key__  = 'XORCISM'

    MutexNameID = Column(Integer, primary_key=True)
    MutexID = Column(Integer)
    MutexName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<MUTEXNAME {self.MutexNameID}>'

class MUTEXNAMES(Base):
    __tablename__ = 'MUTEXNAMES'
    __bind_key__  = 'XORCISM'

    MutexNamesID = Column(Integer, primary_key=True)
    MutexID = Column(Integer, nullable=False)
    MutexNameID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<MUTEXNAMES {self.MutexNamesID}>'

class MUTEXTYPE(Base):
    __tablename__ = 'MUTEXTYPE'
    __bind_key__  = 'XORCISM'

    MutexTypeID = Column(Integer, primary_key=True)
    MutexType = Column(Text)
    MutexTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<MUTEXTYPE {self.MutexTypeID}>'

class NAICS(Base):
    __tablename__ = 'NAICS'
    __bind_key__  = 'XORCISM'

    NAICSID = Column(Integer, primary_key=True)
    NAICSSector = Column(Text, nullable=False)
    NAICSDescription = Column(Text, nullable=False)

    def __repr__(self):
        return f'<NAICS {self.NAICSID}>'

class NAME(Base):
    __tablename__ = 'NAME'
    __bind_key__  = 'XORCISM'

    NameID = Column(Integer, primary_key=True)
    NameText = Column(Text)
    LocaleID = Column(Integer)
    VersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<NAME {self.NameID}>'

class NETROUTE(Base):
    __tablename__ = 'NETROUTE'
    __bind_key__  = 'XORCISM'

    NetRouteID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NETROUTE {self.NetRouteID}>'

class NETWORK(Base):
    __tablename__ = 'NETWORK'
    __bind_key__  = 'XORCISM'

    NetworkID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NETWORK {self.NetworkID}>'

class NETWORKACTIONNAME(Base):
    __tablename__ = 'NETWORKACTIONNAME'
    __bind_key__  = 'XORCISM'

    NetworkActionNameID = Column(Integer, primary_key=True)
    NetworkActionNameName = Column(Text, nullable=False)
    NetworkActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<NETWORKACTIONNAME {self.NetworkActionNameID}>'

class NETWORKCONNECTION(Base):
    __tablename__ = 'NETWORKCONNECTION'
    __bind_key__  = 'XORCISM'

    NetworkConnectionID = Column(Integer, primary_key=True)
    NetworkConnectionGUID = Column(Text)
    tls_used = Column(Integer)
    Creation_Time = Column(Text)
    ProtocolLayer3ID = Column(Integer)
    Layer3_Protocol = Column(Text)
    ProtocolLayer4ID = Column(Integer)
    Layer4_Protocol = Column(Text)
    ProtocolLayer7ID = Column(Integer)
    Layer7_Protocol = Column(Text)
    SourceSocketAddressID = Column(Integer)
    SourceTCPStateID = Column(Integer)
    Source_TCP_State = Column(Text)
    DestinationSocketAddressID = Column(Integer)
    DestinationTCPStateID = Column(Integer)
    Destination_TCP_State = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NETWORKCONNECTION {self.NetworkConnectionID}>'

class NETWORKCONNECTIONLAYER7(Base):
    __tablename__ = 'NETWORKCONNECTIONLAYER7'
    __bind_key__  = 'XORCISM'

    NetworkConnectionLayer7ID = Column(Integer, primary_key=True)
    NetworkConnectionID = Column(Integer)
    NetworkConnectionGUID = Column(Text)
    HTTPSessionID = Column(Integer)
    HTTPSessionGUID = Column(Text)
    DNSQueryID = Column(Integer)
    DNDQueryGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NETWORKCONNECTIONLAYER7 {self.NetworkConnectionLayer7ID}>'

class NETWORKFLOW(Base):
    __tablename__ = 'NETWORKFLOW'
    __bind_key__  = 'XORCISM'

    NetworkFlowID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NETWORKFLOW {self.NetworkFlowID}>'

class NETWORKFLOWLABEL(Base):
    __tablename__ = 'NETWORKFLOWLABEL'
    __bind_key__  = 'XORCISM'

    NetworkFlowLabelID = Column(Integer, primary_key=True)
    Src_Socket_Address = Column(Integer)
    Dest_Socket_Address = Column(Integer)
    IP_Protocol = Column(Integer)
    Ingress_Interface_Index = Column(Integer)
    Egress_Interface_Index = Column(Integer)
    IP_Type_Of_Service = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NETWORKFLOWLABEL {self.NetworkFlowLabelID}>'

class NETWORKINTERFACE(Base):
    __tablename__ = 'NETWORKINTERFACE'
    __bind_key__  = 'XORCISM'

    NetworkInterfaceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NETWORKINTERFACE {self.NetworkInterfaceID}>'

class NETWORKPACKET(Base):
    __tablename__ = 'NETWORKPACKET'
    __bind_key__  = 'XORCISM'

    NetworkPacketID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NETWORKPACKET {self.NetworkPacketID}>'

class NETWORKROUTE(Base):
    __tablename__ = 'NETWORKROUTE'
    __bind_key__  = 'XORCISM'

    NetworkRouteID = Column(Integer, primary_key=True)
    NetworkRouteGUID = Column(Text)
    NetRouteID = Column(Integer)
    is_ipv6 = Column(Integer)
    is_autoconfigure_address = Column(Integer)
    is_immortal = Column(Integer)
    is_loopback = Column(Integer)
    is_publish = Column(Integer)
    DestinationAddressID = Column(Integer)
    OriginAddressID = Column(Integer)
    NetmaskID = Column(Integer)
    GatewayAddressID = Column(Integer)
    Metric = Column(Integer)
    NetworkRouteTypeID = Column(Integer)
    NetworkRouteType = Column(Text)
    ProtocolID = Column(Integer)
    NetworkRouteProtocol = Column(Text)
    NetworkRouteInterface = Column(Text)
    PreferredLifetime = Column(Integer)
    ValidLifetime = Column(Integer)
    RouteAge = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NETWORKROUTE {self.NetworkRouteID}>'

class NETWORKROUTEENTRY(Base):
    __tablename__ = 'NETWORKROUTEENTRY'
    __bind_key__  = 'XORCISM'

    NetworkRouteEntryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NETWORKROUTEENTRY {self.NetworkRouteEntryID}>'

class NETWORKROUTETYPE(Base):
    __tablename__ = 'NETWORKROUTETYPE'
    __bind_key__  = 'XORCISM'

    NetworkRouteTypeID = Column(Integer, primary_key=True)
    RouteType = Column(Text)
    RouteTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NETWORKROUTETYPE {self.NetworkRouteTypeID}>'

class NETWORKSHARE(Base):
    __tablename__ = 'NETWORKSHARE'
    __bind_key__  = 'XORCISM'

    NetworkShareID = Column(Integer, primary_key=True)
    NetworkShareGUID = Column(Text)

    def __repr__(self):
        return f'<NETWORKSHARE {self.NetworkShareID}>'

class NETWORKSHAREACTIONNAME(Base):
    __tablename__ = 'NETWORKSHAREACTIONNAME'
    __bind_key__  = 'XORCISM'

    NetworkShareActionNameID = Column(Integer, primary_key=True)
    NetworkShareActionNameName = Column(Text, nullable=False)
    NetworkShareActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NETWORKSHAREACTIONNAME {self.NetworkShareActionNameID}>'

class NETWORKSOCKET(Base):
    __tablename__ = 'NETWORKSOCKET'
    __bind_key__  = 'XORCISM'

    NetworkSocketID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NETWORKSOCKET {self.NetworkSocketID}>'

class NETWORKSUBNET(Base):
    __tablename__ = 'NETWORKSUBNET'
    __bind_key__  = 'XORCISM'

    NetworkSubnetID = Column(Integer, primary_key=True)
    NetworkSubnetGUID = Column(Text)
    NetworkSubnetName = Column(Text)
    NetworkSubnetDescription = Column(Text)
    NetworkSubnetNumberOfIPAddresses = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<NETWORKSUBNET {self.NetworkSubnetID}>'

class NETWORKSUBNETROUTES(Base):
    __tablename__ = 'NETWORKSUBNETROUTES'
    __bind_key__  = 'XORCISM'

    NetworkSubnetRoutesID = Column(Integer, primary_key=True)
    NetworkSubnetID = Column(Integer)
    NetworkSubnetGUID = Column(Text)
    NetworkRouteID = Column(Integer)
    NetworkRouteGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NETWORKSUBNETROUTES {self.NetworkSubnetRoutesID}>'

class NETWORKZONE(Base):
    __tablename__ = 'NETWORKZONE'
    __bind_key__  = 'XORCISM'

    NetworkZoneID = Column(Integer, primary_key=True)
    NetworkZoneGUID = Column(Text)
    ZoneID = Column(Integer)
    ZoneGUID = Column(Text)
    NetworkZoneName = Column(Text)
    NetworkZoneDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<NETWORKZONE {self.NetworkZoneID}>'

class NETWORKZONEDESCRIPTION(Base):
    __tablename__ = 'NETWORKZONEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    NetworkZoneDescriptionID = Column(Integer, primary_key=True)
    NetworkZoneID = Column(Integer)
    NetworkZoneGUID = Column(Text)
    DescriptionID = Column(Integer)
    DescriptionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NETWORKZONEDESCRIPTION {self.NetworkZoneDescriptionID}>'

class NETWORKZONERESTRICTION(Base):
    __tablename__ = 'NETWORKZONERESTRICTION'
    __bind_key__  = 'XORCISM'

    NetworkZoneRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NETWORKZONERESTRICTION {self.NetworkZoneRestrictionID}>'

class NETWORKZONETAG(Base):
    __tablename__ = 'NETWORKZONETAG'
    __bind_key__  = 'XORCISM'

    NetworkZoneTagID = Column(Integer, primary_key=True)
    ConfidentialityLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<NETWORKZONETAG {self.NetworkZoneTagID}>'

class NEURALNETWORK(Base):
    __tablename__ = 'NEURALNETWORK'
    __bind_key__  = 'XORCISM'

    NeuralNetworkID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<NEURALNETWORK {self.NeuralNetworkID}>'

class NOTIFICATION(Base):
    __tablename__ = 'NOTIFICATION'
    __bind_key__  = 'XORCISM'

    NotificationID = Column(Integer, primary_key=True)
    NotificationGUID = Column(Text)
    BLOB = Column(Text)
    UserID = Column(Text)
    NotificationMessage = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ImportanceID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<NOTIFICATION {self.NotificationID}>'

class OBFUSCATIONTECHNIQUE(Base):
    __tablename__ = 'OBFUSCATIONTECHNIQUE'
    __bind_key__  = 'XORCISM'

    ObfuscationTechniqueID = Column(Integer, primary_key=True)
    ObfuscationTechniqueGUID = Column(Text)
    TechniqueID = Column(Integer)
    ObfuscationTechniqueName = Column(Text, nullable=False)
    ObfuscationTechniqueDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OBFUSCATIONTECHNIQUE {self.ObfuscationTechniqueID}>'

class OBFUSCATIONTECHNIQUETAG(Base):
    __tablename__ = 'OBFUSCATIONTECHNIQUETAG'
    __bind_key__  = 'XORCISM'

    ObfuscationTechniqueTagID = Column(Integer, primary_key=True)
    ObfuscationTechniqueID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OBFUSCATIONTECHNIQUETAG {self.ObfuscationTechniqueTagID}>'

class OBJECTIVE(Base):
    __tablename__ = 'OBJECTIVE'
    __bind_key__  = 'XORCISM'

    ObjectiveID = Column(Integer, primary_key=True)
    ObjectiveGUID = Column(Text)
    ObjectiveCategoryID = Column(Integer)
    ObjectiveVocabularyID = Column(Text)
    ObjectiveName = Column(Text)
    ObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OBJECTIVE {self.ObjectiveID}>'

class OBJECTIVECATEGORY(Base):
    __tablename__ = 'OBJECTIVECATEGORY'
    __bind_key__  = 'XORCISM'

    ObjectiveCategoryID = Column(Integer, primary_key=True)
    ObjectiveCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    ObjectiveCategoryName = Column(Text)
    ObjectiveCategoryDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OBJECTIVECATEGORY {self.ObjectiveCategoryID}>'

class OBJECTIVETAG(Base):
    __tablename__ = 'OBJECTIVETAG'
    __bind_key__  = 'XORCISM'

    ObjectiveTagID = Column(Integer, primary_key=True)
    ObjectiveID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OBJECTIVETAG {self.ObjectiveTagID}>'

class OBJECTRELATIONSHIP(Base):
    __tablename__ = 'OBJECTRELATIONSHIP'
    __bind_key__  = 'XORCISM'

    ObjectRelationshipID = Column(Integer, primary_key=True)
    ObjectRelationshipName = Column(Text, nullable=False)
    ObjectRelationshipDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<OBJECTRELATIONSHIP {self.ObjectRelationshipID}>'

class OBJECTSTATE(Base):
    __tablename__ = 'OBJECTSTATE'
    __bind_key__  = 'XORCISM'

    ObjectStateID = Column(Integer, primary_key=True)
    ObjectStateName = Column(Text, nullable=False)
    ObjectStateDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<OBJECTSTATE {self.ObjectStateID}>'

class OBJECTTYPE(Base):
    __tablename__ = 'OBJECTTYPE'
    __bind_key__  = 'XORCISM'

    ObjectTypeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<OBJECTTYPE {self.ObjectTypeID}>'

class OBSERVATIONMETHOD(Base):
    __tablename__ = 'OBSERVATIONMETHOD'
    __bind_key__  = 'XORCISM'

    ObservationMethodID = Column(Integer, primary_key=True)
    ObservationMethodGUID = Column(Text)
    ObservationMethodName = Column(Text, nullable=False)
    ObservationMethodDescription = Column(Text)
    MeasureSourceID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OBSERVATIONMETHOD {self.ObservationMethodID}>'

class OFFSET(Base):
    __tablename__ = 'OFFSET'
    __bind_key__  = 'XORCISM'

    OffsetID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<OFFSET {self.OffsetID}>'

class ONTOLOGY(Base):
    __tablename__ = 'ONTOLOGY'
    __bind_key__  = 'XORCISM'

    OntologyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ONTOLOGY {self.OntologyID}>'

class OPCODE(Base):
    __tablename__ = 'OPCODE'
    __bind_key__  = 'XORCISM'

    OpcodeID = Column(Integer, primary_key=True)
    OpcodeName = Column(Text, nullable=False)
    OpcodeDescription = Column(Text)
    OpcodeHEXValue = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OPCODE {self.OpcodeID}>'

class OPCODEFORCPE(Base):
    __tablename__ = 'OPCODEFORCPE'
    __bind_key__  = 'XORCISM'

    CPEID = Column(Text, primary_key=True)
    OpcodeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OPCODEFORCPE {self.CPEID}>'

class OPERATIONENUMERATION(Base):
    __tablename__ = 'OPERATIONENUMERATION'
    __bind_key__  = 'XORCISM'

    OperationEnumerationID = Column(Integer, primary_key=True)
    OperationValue = Column(Text, nullable=False)
    OperationDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OPERATIONENUMERATION {self.OperationEnumerationID}>'

class OPERATIONENUMERATIONFORSIMPLEDATATYPE(Base):
    __tablename__ = 'OPERATIONENUMERATIONFORSIMPLEDATATYPE'
    __bind_key__  = 'XORCISM'

    SimpleDataTypeID = Column(Integer, primary_key=True)
    OperationEnumerationID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OPERATIONENUMERATIONFORSIMPLEDATATYPE {self.SimpleDataTypeID}>'

class OPERATORENUMERATION(Base):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'OPERATORENUMERATION'
    __bind_key__  = 'XORCISM'

    OperatorEnumerationID = Column(Integer, primary_key=True)
    OperatorValue = Column(Text, nullable=False)
    OperatorDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OPERATORENUMERATION {self.OperatorEnumerationID}>'

class ORGANISATION(Base):
    __tablename__ = 'ORGANISATION'
    __bind_key__  = 'XORCISM'

    OrganisationID = Column(Integer, primary_key=True)
    OrganisationGUID = Column(Text)
    OrganisationName = Column(Text, nullable=False)
    OrganisationType = Column(Text)
    OrganisationKnownAs = Column(Text)
    industry = Column(Text)
    CountryID = Column(Integer)
    employee_count = Column(Text)
    revenueamount = Column(Integer)
    iso_currency_code = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ORGANISATION {self.OrganisationID}>'

class ORGANISATIONACCESSRECORD(Base):
    __tablename__ = 'ORGANISATIONACCESSRECORD'
    __bind_key__  = 'XORCISM'

    OrganisationAccessRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ORGANISATIONACCESSRECORD {self.OrganisationAccessRecordID}>'

class ORGANISATIONCHANGERECORD(Base):
    __tablename__ = 'ORGANISATIONCHANGERECORD'
    __bind_key__  = 'XORCISM'

    OrganisationChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ORGANISATIONCHANGERECORD {self.OrganisationChangeRecordID}>'

class ORGANISATIONDOMAINNAME(Base):
    __tablename__ = 'ORGANISATIONDOMAINNAME'
    __bind_key__  = 'XORCISM'

    OrganisationDomainNameID = Column(Integer, primary_key=True)
    OrganisationID = Column(Integer, nullable=False)
    OrganisationGUID = Column(Text)
    OrganisationDomainNameRelationship = Column(Text)
    DomainNameID = Column(Integer)
    DomainNameGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ORGANISATIONDOMAINNAME {self.OrganisationDomainNameID}>'

class ORGANISATIONFORTHREATACTORTTP(Base):
    __tablename__ = 'ORGANISATIONFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    ThreatActorTTPOrganisationID = Column(Integer, primary_key=True)
    ThreatActorTTPID = Column(Integer, nullable=False)
    ThreatActorTTPGUID = Column(Text)
    OrganisationID = Column(Integer, nullable=False)
    OrganisationGUID = Column(Text)
    Information_Source = Column(Text)
    ConfidenceLevel = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    notes = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ORGANISATIONFORTHREATACTORTTP {self.ThreatActorTTPOrganisationID}>'

class ORGANISATIONLICENSE(Base):
    __tablename__ = 'ORGANISATIONLICENSE'
    __bind_key__  = 'XORCISM'

    OrganisationLicenseID = Column(Integer, primary_key=True)
    OrganisationID = Column(Integer, nullable=False)
    LicenseID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ORGANISATIONLICENSE {self.OrganisationLicenseID}>'

class ORGANISATIONPOLICY(Base):
    __tablename__ = 'ORGANISATIONPOLICY'
    __bind_key__  = 'XORCISM'

    OrganisationPolicyID = Column(Integer, primary_key=True)
    OrganisationID = Column(Integer, nullable=False)
    PolicyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<ORGANISATIONPOLICY {self.OrganisationPolicyID}>'

class ORGANISATIONPROJECT(Base):
    __tablename__ = 'ORGANISATIONPROJECT'
    __bind_key__  = 'XORCISM'

    OrganisationProjectID = Column(Integer, primary_key=True)
    OrganisationID = Column(Integer)
    OrganisationGUID = Column(Text)
    OrganisationProjectRelationship = Column(Text)
    OrganisationProjectDescription = Column(Text)
    ProjectID = Column(Integer)
    ProjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromdate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ORGANISATIONPROJECT {self.OrganisationProjectID}>'

class ORGANISATIONSCHEDULE(Base):
    __tablename__ = 'ORGANISATIONSCHEDULE'
    __bind_key__  = 'XORCISM'

    OrganisationScheduleID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ORGANISATIONSCHEDULE {self.OrganisationScheduleID}>'

class ORGANISATIONTAG(Base):
    __tablename__ = 'ORGANISATIONTAG'
    __bind_key__  = 'XORCISM'

    OrganisationTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ORGANISATIONTAG {self.OrganisationTagID}>'

class ORGANISATIONTECHNOLOGY(Base):
    __tablename__ = 'ORGANISATIONTECHNOLOGY'
    __bind_key__  = 'XORCISM'

    OrganisationTechnologyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ORGANISATIONTECHNOLOGY {self.OrganisationTechnologyID}>'

class ORGANISATIONWORKINGHOURS(Base):
    __tablename__ = 'ORGANISATIONWORKINGHOURS'
    __bind_key__  = 'XORCISM'

    OrganisationWorkingHoursID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ORGANISATIONWORKINGHOURS {self.OrganisationWorkingHoursID}>'

class ORGANIZATIONALUNIT(Base):
    __tablename__ = 'ORGANIZATIONALUNIT'
    __bind_key__  = 'XORCISM'

    OrganizationalUnitID = Column(Integer, primary_key=True)
    OrganizationalUnitGUID = Column(Text)
    OUName = Column(Text, nullable=False)
    OUDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ORGANIZATIONALUNIT {self.OrganizationalUnitID}>'

class ORGANIZATIONALUNITFORORGANISATION(Base):
    __tablename__ = 'ORGANIZATIONALUNITFORORGANISATION'
    __bind_key__  = 'XORCISM'

    OrganisationUnitsID = Column(Integer, primary_key=True)
    OrganisationID = Column(Integer, nullable=False)
    OrganisationGUID = Column(Text)
    OrganizationalUnitID = Column(Integer, nullable=False)
    OrganizationalUnitGUID = Column(Text)
    OUChildName = Column(Text)
    OUChildDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ORGANIZATIONALUNITFORORGANISATION {self.OrganisationUnitsID}>'

class ORGANIZATIONALUNITPOLICY(Base):
    __tablename__ = 'ORGANIZATIONALUNITPOLICY'
    __bind_key__  = 'XORCISM'

    OrganizationalUnitPolicyID = Column(Integer, primary_key=True)
    OrganizationalUnitID = Column(Integer, nullable=False)
    OrganizationalUnitGUID = Column(Text)
    OrganizationalUnitRelationship = Column(Text)
    PolicyID = Column(Integer, nullable=False)
    PolicyGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ORGANIZATIONALUNITPOLICY {self.OrganizationalUnitPolicyID}>'

class OS(Base):
    __tablename__ = 'OS'
    __bind_key__  = 'XORCISM'

    OSID = Column(Integer, primary_key=True)
    Operating_System_Name = Column(Text)
    OSname = Column(Text, nullable=False)
    OSversion = Column(Text)
    LocaleID = Column(Integer)
    OSlang = Column(Text)
    OSSP = Column(Text)
    Platform = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OS {self.OSID}>'

class OSCLASS(Base):
    __tablename__ = 'OSCLASS'
    __bind_key__  = 'XORCISM'

    OSClassID = Column(Integer, primary_key=True)
    OSClassGUID = Column(Text)
    Operating_System_Class_Description = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OSCLASS {self.OSClassID}>'

class OSFAMILY(Base):
    __tablename__ = 'OSFAMILY'
    __bind_key__  = 'XORCISM'

    OSFamilyID = Column(Integer, primary_key=True)
    FamilyName = Column(Text)
    FamilyDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OSFAMILY {self.OSFamilyID}>'

class OSFAMILYFOROS(Base):
    __tablename__ = 'OSFAMILYFOROS'
    __bind_key__  = 'XORCISM'

    OSFamilyOSID = Column(Integer, primary_key=True)
    OSID = Column(Integer, nullable=False)
    OSFamilyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<OSFAMILYFOROS {self.OSFamilyOSID}>'

class OSFAMILYPLATFORM(Base):
    __tablename__ = 'OSFAMILYPLATFORM'
    __bind_key__  = 'XORCISM'

    OSFamilyPlatformID = Column(Integer, primary_key=True)
    OSFamilyID = Column(Integer)
    PlatformID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OSFAMILYPLATFORM {self.OSFamilyPlatformID}>'

class OSILAYER(Base):
    __tablename__ = 'OSILAYER'
    __bind_key__  = 'XORCISM'

    OSILayerID = Column(Integer, primary_key=True)
    OSILayerName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OSILAYER {self.OSILayerID}>'

class OSILAYERFORATTACKSURFACE(Base):
    __tablename__ = 'OSILAYERFORATTACKSURFACE'
    __bind_key__  = 'XORCISM'

    AttackSurfaceOSILayerID = Column(Integer, primary_key=True)
    OSILayerID = Column(Integer, nullable=False)
    AttackSurfaceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<OSILAYERFORATTACKSURFACE {self.AttackSurfaceOSILayerID}>'

class OSINSTRUCTIONMEMORYADDRESS(Base):
    __tablename__ = 'OSINSTRUCTIONMEMORYADDRESS'
    __bind_key__  = 'XORCISM'

    OSInstructionMemoryAddressID = Column(Integer, primary_key=True)
    OSID = Column(Integer, nullable=False)
    InstructionID = Column(Integer, nullable=False)
    MemoryAddressID = Column(Integer, nullable=False)
    OSPatchLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OSINSTRUCTIONMEMORYADDRESS {self.OSInstructionMemoryAddressID}>'

class OSPATCH(Base):
    __tablename__ = 'OSPATCH'
    __bind_key__  = 'XORCISM'

    OSPatchID = Column(Integer, primary_key=True)
    OSPatchGUID = Column(Text)
    OSID = Column(Integer)
    OSGUID = Column(Text)
    PatchID = Column(Integer)
    PatchGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionMethodGUID = Column(Text)
    TrustLevelID = Column(Integer)
    TrustLevelGUID = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OSPATCH {self.OSPatchID}>'

class OSPATCHLEVEL(Base):
    __tablename__ = 'OSPATCHLEVEL'
    __bind_key__  = 'XORCISM'

    OSPatchLevelID = Column(Integer, primary_key=True)
    OSPatchLevelGUID = Column(Text, nullable=False)
    OSPatchLevelDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<OSPATCHLEVEL {self.OSPatchLevelID}>'

class OSPATCHLEVELPATCH(Base):
    __tablename__ = 'OSPATCHLEVELPATCH'
    __bind_key__  = 'XORCISM'

    OSPatchesID = Column(Integer, primary_key=True)
    OSPatchLevelID = Column(Integer, nullable=False)
    OSPatchID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OSPATCHLEVELPATCH {self.OSPatchesID}>'

class OUTPUTFIELD(Base):
    __tablename__ = 'OUTPUTFIELD'
    __bind_key__  = 'XORCISM'

    OutputFieldID = Column(Integer, primary_key=True)
    FieldID = Column(Integer)

    def __repr__(self):
        return f'<OUTPUTFIELD {self.OutputFieldID}>'

class OWASPTOP10(Base):
    __tablename__ = 'OWASPTOP10'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ID = Column(Integer, primary_key=True)
    OWASPTOP10GUID = Column(Text)
    OWASPTOP10RefID = Column(Text)
    OWASPName = Column(Text, nullable=False)
    OWASPDescription = Column(Text)
    Detectability = Column(Text)
    Rank = Column(Integer, nullable=False)
    YearTop10 = Column(Integer)
    ReferenceURL = Column(Text)
    OWASPTOP10Type = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)

    def __repr__(self):
        return f'<OWASPTOP10 {self.OWASPTOP10ID}>'

class OWASPTOP10ATTACKVECTOR(Base):
    __tablename__ = 'OWASPTOP10ATTACKVECTOR'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ID = Column(Integer, primary_key=True)
    AttackVectorID = Column(Integer, nullable=False)
    ExploitabilityLevel = Column(Text)

    def __repr__(self):
        return f'<OWASPTOP10ATTACKVECTOR {self.OWASPTOP10ID}>'

class OWASPTOP10DEFENSETOOLTYPE(Base):
    __tablename__ = 'OWASPTOP10DEFENSETOOLTYPE'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ID = Column(Integer, primary_key=True)
    DefenseToolTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OWASPTOP10DEFENSETOOLTYPE {self.OWASPTOP10ID}>'

class OWASPTOP10DETECTABILITY(Base):
    __tablename__ = 'OWASPTOP10DETECTABILITY'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ID = Column(Integer, primary_key=True)
    DetectabilityID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OWASPTOP10DETECTABILITY {self.OWASPTOP10ID}>'

class OWASPTOP10EXPLOITABILITY(Base):
    __tablename__ = 'OWASPTOP10EXPLOITABILITY'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ExploitabilityID = Column(Integer, primary_key=True)
    OWASPTOP10ID = Column(Integer, nullable=False)
    ExploitabilityID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OWASPTOP10EXPLOITABILITY {self.OWASPTOP10ExploitabilityID}>'

class OWASPTOP10IMPACT(Base):
    __tablename__ = 'OWASPTOP10IMPACT'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ID = Column(Integer, primary_key=True)
    ImpactID = Column(Integer, nullable=False)
    ImpactSeverity = Column(Text)

    def __repr__(self):
        return f'<OWASPTOP10IMPACT {self.OWASPTOP10ID}>'

class OWASPTOP10MAPPING(Base):
    __tablename__ = 'OWASPTOP10MAPPING'
    __bind_key__  = 'XORCISM'

    OWASPTOP10MappingID = Column(Integer, primary_key=True)
    OWASPTOP10RefID = Column(Integer, nullable=False)
    OWASPNameRef = Column(Text)
    RankRef = Column(Integer)
    YearRef = Column(Integer)
    OWASPTOP10SubjectID = Column(Integer, nullable=False)
    OWASPNameSubject = Column(Text)
    RankSubject = Column(Integer)
    YearSubject = Column(Integer)
    CreationDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OWASPTOP10MAPPING {self.OWASPTOP10MappingID}>'

class OWASPTOP10PREVALENCE(Base):
    __tablename__ = 'OWASPTOP10PREVALENCE'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ID = Column(Integer, primary_key=True)
    PrevalenceID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OWASPTOP10PREVALENCE {self.OWASPTOP10ID}>'

class OWASPTOP10REFERENCE(Base):
    __tablename__ = 'OWASPTOP10REFERENCE'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<OWASPTOP10REFERENCE {self.OWASPTOP10ID}>'

class OWASPTOP10TOOLINFORMATION(Base):
    __tablename__ = 'OWASPTOP10TOOLINFORMATION'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ID = Column(Integer, primary_key=True)
    ToolInformationID = Column(Integer, nullable=False)
    Relationship = Column(Text)

    def __repr__(self):
        return f'<OWASPTOP10TOOLINFORMATION {self.OWASPTOP10ID}>'

class OWNERSHIP(Base):
    __tablename__ = 'OWNERSHIP'
    __bind_key__  = 'XORCISM'

    OwnershipID = Column(Integer, primary_key=True)
    OwnershipName = Column(Text)
    OwnershipDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<OWNERSHIP {self.OwnershipID}>'

class PACKAGEINTENT(Base):
    __tablename__ = 'PACKAGEINTENT'
    __bind_key__  = 'XORCISM'

    PackageIntentID = Column(Integer, primary_key=True)
    PackageIntentGUID = Column(Text)
    PackageIntentName = Column(Text)
    PackageIntentDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromdate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    ImportanceID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<PACKAGEINTENT {self.PackageIntentID}>'

class PACKAGING(Base):
    __tablename__ = 'PACKAGING'
    __bind_key__  = 'XORCISM'

    PackagingID = Column(Integer, primary_key=True)
    PackagingGUID = Column(Text)
    PackagingLayerName = Column(Text, nullable=False)
    PackagingDescription = Column(Text)
    is_encrypted = Column(Integer)
    is_compressed = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    RepositoryID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)

    def __repr__(self):
        return f'<PACKAGING {self.PackagingID}>'

class PACKAGINGCOMPRESSION(Base):
    __tablename__ = 'PACKAGINGCOMPRESSION'
    __bind_key__  = 'XORCISM'

    PackagingCompressionID = Column(Integer, primary_key=True)
    PackagingCompressionGUID = Column(Text)
    PackagingCompressionDescription = Column(Text)
    PackagingID = Column(Integer, nullable=False)
    PackagingGUID = Column(Text)
    CompressionID = Column(Integer, nullable=False)
    CompressionGUID = Column(Text)
    LayerOrder = Column(Integer, nullable=False)
    CompressionPassword = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PACKAGINGCOMPRESSION {self.PackagingCompressionID}>'

class PACKAGINGENCODING(Base):
    __tablename__ = 'PACKAGINGENCODING'
    __bind_key__  = 'XORCISM'

    PackagingEncodingID = Column(Integer, primary_key=True)
    PackagingEncodingGUID = Column(Text)
    PackagingID = Column(Integer, nullable=False)
    PackagingGUID = Column(Text)
    EncodingID = Column(Integer, nullable=False)
    EncodingGUID = Column(Text)
    LayerOrder = Column(Integer, nullable=False)
    algorithm = Column(Text)
    character_set = Column(Text)
    CharacterSetID = Column(Integer)
    custom_character_set_ref = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PACKAGINGENCODING {self.PackagingEncodingID}>'

class PACKAGINGENCRYPTION(Base):
    __tablename__ = 'PACKAGINGENCRYPTION'
    __bind_key__  = 'XORCISM'

    PackagingEncryptionID = Column(Integer, primary_key=True)
    PackagingEncryptionGUID = Column(Text)
    PackagingID = Column(Integer, nullable=False)
    PackagingGUID = Column(Text)
    EncryptionID = Column(Integer, nullable=False)
    EncryptionGUID = Column(Text)
    LayerOrder = Column(Integer, nullable=False)
    encryption_key = Column(Text)
    encryption_key_ref = Column(Text)
    PackagingEncryptionDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PACKAGINGENCRYPTION {self.PackagingEncryptionID}>'

class PARAGRAPH(Base):
    __tablename__ = 'PARAGRAPH'
    __bind_key__  = 'XORCISM'

    ParagraphID = Column(Integer, primary_key=True)
    SectionID = Column(Integer)

    def __repr__(self):
        return f'<PARAGRAPH {self.ParagraphID}>'

class PARAMETER(Base):
    __tablename__ = 'PARAMETER'
    __bind_key__  = 'XORCISM'

    ParameterID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PARAMETER {self.ParameterID}>'

class PARAMETERDESCRIPTION(Base):
    __tablename__ = 'PARAMETERDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ParameterDescriptionID = Column(Integer, primary_key=True)
    ParameterID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PARAMETERDESCRIPTION {self.ParameterDescriptionID}>'

class PARAMETERSFORPROVIDER(Base):
    __tablename__ = 'PARAMETERSFORPROVIDER'
    __bind_key__  = 'XORCISM'

    ID = Column(Integer, primary_key=True)
    ServiceCategoryID = Column(Integer, nullable=False)
    Strategy = Column(Text)
    Policy = Column(Text)
    ProviderID = Column(Integer, nullable=False)
    Parameters = Column(Text)

    def __repr__(self):
        return f'<PARAMETERSFORPROVIDER {self.ID}>'

class PARAMETERTAG(Base):
    __tablename__ = 'PARAMETERTAG'
    __bind_key__  = 'XORCISM'

    ParameterTagID = Column(Integer, primary_key=True)
    ParameterID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PARAMETERTAG {self.ParameterTagID}>'

class PASSWORDQUESTION(Base):
    __tablename__ = 'PASSWORDQUESTION'
    __bind_key__  = 'XORCISM'

    PasswordQuestionID = Column(Integer, primary_key=True)
    Label = Column(Text)
    Value = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PASSWORDQUESTION {self.PasswordQuestionID}>'

class PATCH(Base):
    __tablename__ = 'PATCH'
    __bind_key__  = 'XORCISM'

    PatchID = Column(Integer, primary_key=True)
    PatchGUID = Column(Text)
    PatchVocabularyID = Column(Text)
    PatchTitle = Column(Text)
    PatchDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PATCH {self.PatchID}>'

class PATCHFILE(Base):
    __tablename__ = 'PATCHFILE'
    __bind_key__  = 'XORCISM'

    PatchFileID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PATCHFILE {self.PatchFileID}>'

class PATCHREFERENCE(Base):
    __tablename__ = 'PATCHREFERENCE'
    __bind_key__  = 'XORCISM'

    PatchReferenceID = Column(Integer, primary_key=True)
    PatchID = Column(Integer, nullable=False)
    PatchGUID = Column(Text)
    PatchReferenceRelationship = Column(Text)
    PatchReferenceDescription = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PATCHREFERENCE {self.PatchReferenceID}>'

class PATCHREPOSITORY(Base):
    __tablename__ = 'PATCHREPOSITORY'
    __bind_key__  = 'XORCISM'

    PatchRepositoryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PATCHREPOSITORY {self.PatchRepositoryID}>'

class PATTERNFIELDGROUP(Base):
    __tablename__ = 'PATTERNFIELDGROUP'
    __bind_key__  = 'XORCISM'

    PatternFieldGroupID = Column(Integer, primary_key=True)
    ConditionApplicationID = Column(Integer)
    apply_condition = Column(Text)
    bit_mask = Column(Text)
    ConditionID = Column(Integer)
    condition = Column(Text)
    has_changed = Column(Integer)
    PatternTypeID = Column(Integer)
    pattern_type = Column(Text)
    regex_syntax = Column(Text)
    trend = Column(Integer)

    def __repr__(self):
        return f'<PATTERNFIELDGROUP {self.PatternFieldGroupID}>'

class PATTERNTYPE(Base):
    __tablename__ = 'PATTERNTYPE'
    __bind_key__  = 'XORCISM'

    PatternTypeID = Column(Integer, primary_key=True)
    PatternTypeName = Column(Text, nullable=False)
    PatternTypeDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PATTERNTYPE {self.PatternTypeID}>'

class PAYLOAD(Base):
    __tablename__ = 'PAYLOAD'
    __bind_key__  = 'XORCISM'

    PayloadID = Column(Integer, primary_key=True)
    AttackPayloadID = Column(Integer)
    PayloadGUID = Column(Text)
    PayloadName = Column(Text)
    PayloadText = Column(Text)
    PayloadDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PAYLOAD {self.PayloadID}>'

class PCAPFILE(Base):
    __tablename__ = 'PCAPFILE'
    __bind_key__  = 'XORCISM'

    PCAPFileID = Column(Integer, primary_key=True)
    FileID = Column(Integer)

    def __repr__(self):
        return f'<PCAPFILE {self.PCAPFileID}>'

class PDFFILE(Base):
    __tablename__ = 'PDFFILE'
    __bind_key__  = 'XORCISM'

    PDFFileID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PDFFILE {self.PDFFileID}>'

class PERFORMANCEREQUIREMENT(Base):
    __tablename__ = 'PERFORMANCEREQUIREMENT'
    __bind_key__  = 'XORCISM'

    PerformanceRequirementID = Column(Integer, primary_key=True)
    RequirementID = Column(Integer)
    RequirementGUID = Column(Text)
    PerformanceRequirementGUID = Column(Text)
    PerformanceRequirementTitle = Column(Text)
    PerformanceRequirementDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PERFORMANCEREQUIREMENT {self.PerformanceRequirementID}>'

class PERIMETER(Base):
    __tablename__ = 'PERIMETER'
    __bind_key__  = 'XORCISM'

    PerimeterID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PERIMETER {self.PerimeterID}>'

class PERIMETERDESCRIPTION(Base):
    __tablename__ = 'PERIMETERDESCRIPTION'
    __bind_key__  = 'XORCISM'

    PerimeterDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PERIMETERDESCRIPTION {self.PerimeterDescriptionID}>'

class PERIMETERZONE(Base):
    __tablename__ = 'PERIMETERZONE'
    __bind_key__  = 'XORCISM'

    PerimeterZoneID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PERIMETERZONE {self.PerimeterZoneID}>'

class PERMISSION(Base):
    __tablename__ = 'PERMISSION'
    __bind_key__  = 'XORCISM'

    PermissionID = Column(Integer, primary_key=True)
    PermissionName = Column(Text)
    PermissionDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)
    CreationObjectID = Column(Integer)

    def __repr__(self):
        return f'<PERMISSION {self.PermissionID}>'

class PERMISSIONDESCRIPTION(Base):
    __tablename__ = 'PERMISSIONDESCRIPTION'
    __bind_key__  = 'XORCISM'

    PermissionDescriptionID = Column(Integer, primary_key=True)
    PermissionID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<PERMISSIONDESCRIPTION {self.PermissionDescriptionID}>'

class PERSISTENCEPROPERTIES(Base):
    __tablename__ = 'PERSISTENCEPROPERTIES'
    __bind_key__  = 'XORCISM'

    PersistencePropertiesID = Column(Integer, primary_key=True)
    PersistencePropertiesName = Column(Text)
    PersistencePropertiesDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSISTENCEPROPERTIES {self.PersistencePropertiesID}>'

class PERSISTENCESTRATEGICOBJECTIVE(Base):
    __tablename__ = 'PERSISTENCESTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    PersistenceStrategicObjectiveID = Column(Integer, primary_key=True)
    PersistenceStrategicObjectiveName = Column(Text)
    PersistenceStrategicObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSISTENCESTRATEGICOBJECTIVE {self.PersistenceStrategicObjectiveID}>'

class PERSISTENCETACTICALOBJECTIVE(Base):
    __tablename__ = 'PERSISTENCETACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    PersistenceTacticalObjectiveID = Column(Integer, primary_key=True)
    PersistenceTacticalObjectiveName = Column(Text)
    PersistenceTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<PERSISTENCETACTICALOBJECTIVE {self.PersistenceTacticalObjectiveID}>'

class PERSON(Base):
    __tablename__ = 'PERSON'
    __bind_key__  = 'XORCISM'

    PersonID = Column(Integer, primary_key=True)
    PrecedingTitle = Column(Text)
    Title = Column(Text)
    FirstName = Column(Text)
    MiddleName = Column(Text)
    LastNamePrefix = Column(Text)
    LastName = Column(Text)
    FullName = Column(Text)
    OtherName = Column(Text)
    Alias = Column(Text)
    Suffix = Column(Text)
    GeneralSuffix = Column(Text)
    PersonFunction = Column(Text)
    email = Column(Text)
    CreatedDate = Column(Text)
    ModifiedDate = Column(Text)
    birthdate = Column(Text)
    BLOB = Column(Text)
    TrustLevelID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PERSON {self.PersonID}>'

class PERSONASSURANCE(Base):
    __tablename__ = 'PERSONASSURANCE'
    __bind_key__  = 'XORCISM'

    PersonAssuranceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PERSONASSURANCE {self.PersonAssuranceID}>'

class PERSONBLACKLIST(Base):
    __tablename__ = 'PERSONBLACKLIST'
    __bind_key__  = 'XORCISM'

    PersonBlacklistID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer)
    AssetID = Column(Integer)
    PhysicalLocationID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<PERSONBLACKLIST {self.PersonBlacklistID}>'

class PERSONCERTIFICATION(Base):
    __tablename__ = 'PERSONCERTIFICATION'
    __bind_key__  = 'XORCISM'

    PersonCertificationID = Column(Integer, primary_key=True)
    PersonID = Column(Integer)
    CertificationID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSONCERTIFICATION {self.PersonCertificationID}>'

class PERSONDEVICE(Base):
    __tablename__ = 'PERSONDEVICE'
    __bind_key__  = 'XORCISM'

    PersonDeviceID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    DeviceID = Column(Integer, nullable=False)
    BLOB = Column(Text)
    RACIValue = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<PERSONDEVICE {self.PersonDeviceID}>'

class PERSONDOMAINNAME(Base):
    __tablename__ = 'PERSONDOMAINNAME'
    __bind_key__  = 'XORCISM'

    PersonDomainNameID = Column(Integer, primary_key=True)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    PersonDomainNameRelationship = Column(Text)
    DomainNameID = Column(Integer)
    DomainNameGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSONDOMAINNAME {self.PersonDomainNameID}>'

class PERSONFORAPPLICATION(Base):
    __tablename__ = 'PERSONFORAPPLICATION'
    __bind_key__  = 'XORCISM'

    ApplicationID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    RelationShip = Column(Text)
    RACIValue = Column(Text)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<PERSONFORAPPLICATION {self.ApplicationID}>'

class PERSONFORASSET(Base):
    __tablename__ = 'PERSONFORASSET'
    __bind_key__  = 'XORCISM'

    PersonID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    relationshiptype = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    RACIValue = Column(Text)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<PERSONFORASSET {self.PersonID}>'

class PERSONFORINCIDENT(Base):
    __tablename__ = 'PERSONFORINCIDENT'
    __bind_key__  = 'XORCISM'

    IncidentPersonID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    IncidentID = Column(Integer, nullable=False)
    IncidentPersonRole = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PERSONFORINCIDENT {self.IncidentPersonID}>'

class PERSONFORORGANISATION(Base):
    __tablename__ = 'PERSONFORORGANISATION'
    __bind_key__  = 'XORCISM'

    PersonOrganisationID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer, nullable=False)
    relationshiptype = Column(Text, nullable=False)
    ScheduleID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    RACIValue = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSONFORORGANISATION {self.PersonOrganisationID}>'

class PERSONFORPERSONGROUP(Base):
    __tablename__ = 'PERSONFORPERSONGROUP'
    __bind_key__  = 'XORCISM'

    PersonGroupPersonID = Column(Integer, primary_key=True)
    PersonGroupID = Column(Integer, nullable=False)
    PersonID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PERSONFORPERSONGROUP {self.PersonGroupPersonID}>'

class PERSONFORPROJECT(Base):
    __tablename__ = 'PERSONFORPROJECT'
    __bind_key__  = 'XORCISM'

    ProjectPersonID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer, nullable=False)
    ProjectGUID = Column(Text)
    PersonID = Column(Integer, nullable=False)
    PersonGUID = Column(Text)
    PersonRole = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    TrustLevelID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSONFORPROJECT {self.ProjectPersonID}>'

class PERSONFORTHREATACTORTTP(Base):
    __tablename__ = 'PERSONFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    ThreatActorTTPPersonID = Column(Integer, primary_key=True)
    ThreatActorTTPPersonGUID = Column(Text)
    PersonID = Column(Integer, nullable=False)
    PersonGUID = Column(Text)
    ThreatActorTTPPersonRelationship = Column(Text)
    ThreatActorTTPID = Column(Integer, nullable=False)
    ThreatActorTTPGUID = Column(Text)
    Information_Source = Column(Text)
    ConfidenceLevel = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    notes = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PERSONFORTHREATACTORTTP {self.ThreatActorTTPPersonID}>'

class PERSONGEOLOCATION(Base):
    __tablename__ = 'PERSONGEOLOCATION'
    __bind_key__  = 'XORCISM'

    PersonGeoLocationID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    PersonGUID = Column(Text)
    GeoLocationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSONGEOLOCATION {self.PersonGeoLocationID}>'

class PERSONGROUP(Base):
    __tablename__ = 'PERSONGROUP'
    __bind_key__  = 'XORCISM'

    PersonGroupID = Column(Integer, primary_key=True)
    PersonGroupName = Column(Text, nullable=False)
    PersonGroupDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<PERSONGROUP {self.PersonGroupID}>'

class PERSONLICENSE(Base):
    __tablename__ = 'PERSONLICENSE'
    __bind_key__  = 'XORCISM'

    PersonLicenseID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    PersonGUID = Column(Text)
    LicenseID = Column(Integer, nullable=False)
    LicenseGUID = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSONLICENSE {self.PersonLicenseID}>'

class PERSONPERMISSION(Base):
    __tablename__ = 'PERSONPERMISSION'
    __bind_key__  = 'XORCISM'

    PersonPermissionID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    PermissionID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<PERSONPERMISSION {self.PersonPermissionID}>'

class PERSONPHYSICALLOCATION(Base):
    __tablename__ = 'PERSONPHYSICALLOCATION'
    __bind_key__  = 'XORCISM'

    PersonPhysicalLocationID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    PersonGUID = Column(Text)
    PhysicalLocationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSONPHYSICALLOCATION {self.PersonPhysicalLocationID}>'

class PERSONSCHEDULE(Base):
    __tablename__ = 'PERSONSCHEDULE'
    __bind_key__  = 'XORCISM'

    PersonScheduleID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PERSONSCHEDULE {self.PersonScheduleID}>'

class PERSONSKILL(Base):
    __tablename__ = 'PERSONSKILL'
    __bind_key__  = 'XORCISM'

    PersonSkillID = Column(Integer, primary_key=True)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    SkillID = Column(Integer)
    SkillGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PERSONSKILL {self.PersonSkillID}>'

class PERSONTAG(Base):
    __tablename__ = 'PERSONTAG'
    __bind_key__  = 'XORCISM'

    PersonTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PERSONTAG {self.PersonTagID}>'

class PERSONWHITELIST(Base):
    __tablename__ = 'PERSONWHITELIST'
    __bind_key__  = 'XORCISM'

    PersonWhitelistID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer)
    AssetID = Column(Integer)
    PhysicalLocationID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<PERSONWHITELIST {self.PersonWhitelistID}>'

class PERSONWORKINGHOURS(Base):
    __tablename__ = 'PERSONWORKINGHOURS'
    __bind_key__  = 'XORCISM'

    PersonWorkingHoursID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PERSONWORKINGHOURS {self.PersonWorkingHoursID}>'

class PGPSIGNATURE(Base):
    __tablename__ = 'PGPSIGNATURE'
    __bind_key__  = 'XORCISM'

    PGPSignatureID = Column(Integer, primary_key=True)
    SignatureID = Column(Integer)

    def __repr__(self):
        return f'<PGPSIGNATURE {self.PGPSignatureID}>'

class PHASE(Base):
    __tablename__ = 'PHASE'
    __bind_key__  = 'XORCISM'

    PhaseID = Column(Integer, primary_key=True)
    PhaseGUID = Column(Text)
    PhaseName = Column(Text)
    PhaseDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PHASE {self.PhaseID}>'

class PHASEMAPPING(Base):
    __tablename__ = 'PHASEMAPPING'
    __bind_key__  = 'XORCISM'

    PhaseMappingID = Column(Integer, primary_key=True)
    PhaseRefID = Column(Integer)
    PhaseRefGUID = Column(Text)
    PhaseRelationship = Column(Text)
    PhaseMappingDescription = Column(Text)
    PhaseSubjectID = Column(Integer)
    PhaseSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PHASEMAPPING {self.PhaseMappingID}>'

class PHASETAG(Base):
    __tablename__ = 'PHASETAG'
    __bind_key__  = 'XORCISM'

    PhaseTagID = Column(Integer, primary_key=True)
    PhaseID = Column(Integer)
    PhaseGUID = Column(Text)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PHASETAG {self.PhaseTagID}>'

class PHONECALL(Base):
    __tablename__ = 'PHONECALL'
    __bind_key__  = 'XORCISM'

    PhoneCallID = Column(Integer, primary_key=True)
    TelephoneCallID = Column(Integer)
    duration = Column(Text)
    isSpam = Column(Integer)
    isSocialEngineering = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PHONECALL {self.PhoneCallID}>'

class PHONECALLTAG(Base):
    __tablename__ = 'PHONECALLTAG'
    __bind_key__  = 'XORCISM'

    PhoneCallTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PHONECALLTAG {self.PhoneCallTagID}>'

class PHYSICALLOCATION(Base):
    __tablename__ = 'PHYSICALLOCATION'
    __bind_key__  = 'XORCISM'

    PhysicalLocationID = Column(Integer, primary_key=True)
    PhysicalLocationName = Column(Text, nullable=False)
    PhysicalLocationDescription = Column(Text)
    TrustLevelID = Column(Integer)
    VocabularyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PHYSICALLOCATION {self.PhysicalLocationID}>'

class PHYSICALLOCATIONASSURANCE(Base):
    __tablename__ = 'PHYSICALLOCATIONASSURANCE'
    __bind_key__  = 'XORCISM'

    PhysicalLocationAssuranceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PHYSICALLOCATIONASSURANCE {self.PhysicalLocationAssuranceID}>'

class PHYSICALLOCATIONCLASSIFICATION(Base):
    __tablename__ = 'PHYSICALLOCATIONCLASSIFICATION'
    __bind_key__  = 'XORCISM'

    PhysicalLocationClassificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PHYSICALLOCATIONCLASSIFICATION {self.PhysicalLocationClassificationID}>'

class PHYSICALLOCATIONCONTROL(Base):
    __tablename__ = 'PHYSICALLOCATIONCONTROL'
    __bind_key__  = 'XORCISM'

    PhysicalLocationControlID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PHYSICALLOCATIONCONTROL {self.PhysicalLocationControlID}>'

class PHYSICALLOCATIONDESCRIPTION(Base):
    __tablename__ = 'PHYSICALLOCATIONDESCRIPTION'
    __bind_key__  = 'XORCISM'

    PhysicalLocationDescriptionID = Column(Integer, primary_key=True)
    PhysicalLocationID = Column(Integer, nullable=False)
    PhysicalLocationGUID = Column(Text)
    DescriptionID = Column(Integer)
    DescriptionGUID = Column(Text)
    ConfidentialityLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PHYSICALLOCATIONDESCRIPTION {self.PhysicalLocationDescriptionID}>'

class PHYSICALLOCATIONRESTRICTION(Base):
    __tablename__ = 'PHYSICALLOCATIONRESTRICTION'
    __bind_key__  = 'XORCISM'

    PhysicalLocationRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PHYSICALLOCATIONRESTRICTION {self.PhysicalLocationRestrictionID}>'

class PHYSICALLOCATIONSECURITYCONTROL(Base):
    __tablename__ = 'PHYSICALLOCATIONSECURITYCONTROL'
    __bind_key__  = 'XORCISM'

    PhysicalLocationSecurityControlID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PHYSICALLOCATIONSECURITYCONTROL {self.PhysicalLocationSecurityControlID}>'

class PHYSICALLOCATIONTAG(Base):
    __tablename__ = 'PHYSICALLOCATIONTAG'
    __bind_key__  = 'XORCISM'

    PhysicalLocationTagID = Column(Integer, primary_key=True)
    PhysicalLocationID = Column(Integer)
    PhysicalLocationGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    ConfidentialityLevelID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PHYSICALLOCATIONTAG {self.PhysicalLocationTagID}>'

class PHYSIOLOGICALCHARACTERISTIC(Base):
    __tablename__ = 'PHYSIOLOGICALCHARACTERISTIC'
    __bind_key__  = 'XORCISM'

    PhysiologicalCharacteristicID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PHYSIOLOGICALCHARACTERISTIC {self.PhysiologicalCharacteristicID}>'

class PIPEOBJECT(Base):
    __tablename__ = 'PIPEOBJECT'
    __bind_key__  = 'XORCISM'

    PipeObjectID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PIPEOBJECT {self.PipeObjectID}>'

class PKI(Base):
    __tablename__ = 'PKI'
    __bind_key__  = 'XORCISM'

    PKIID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PKI {self.PKIID}>'

class PLAN(Base):
    __tablename__ = 'PLAN'
    __bind_key__  = 'XORCISM'

    PlanID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PLAN {self.PlanID}>'

class PLATFORM(Base):
    __tablename__ = 'PLATFORM'
    __bind_key__  = 'XORCISM'

    PlatformID = Column(Integer, primary_key=True)
    PlatformGUID = Column(Text)
    PlatformName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    PlatformDescription = Column(Text)
    structuring_format = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PLATFORM {self.PlatformID}>'

class PLATFORMFORCCE(Base):
    __tablename__ = 'PLATFORMFORCCE'
    __bind_key__  = 'XORCISM'

    CCEPlatformID = Column(Integer, primary_key=True)
    CCEID = Column(Integer)
    PlatformID = Column(Integer, nullable=False)
    cce_id = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PLATFORMFORCCE {self.CCEPlatformID}>'

class PLATFORMFORTECHNICALCONTEXT(Base):
    __tablename__ = 'PLATFORMFORTECHNICALCONTEXT'
    __bind_key__  = 'XORCISM'

    TechnicalContextPlatformID = Column(Integer, primary_key=True)
    TechnicalContextPlatformGUID = Column(Text)
    PlatformID = Column(Integer, nullable=False)
    PlatformGUID = Column(Text)
    TechnicalContextID = Column(Integer, nullable=False)
    TechnicalContextGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PLATFORMFORTECHNICALCONTEXT {self.TechnicalContextPlatformID}>'

class PLATFORMMAPPING(Base):
    __tablename__ = 'PLATFORMMAPPING'
    __bind_key__  = 'XORCISM'

    PlatformMappingID = Column(Integer, primary_key=True)
    PlaformRefID = Column(Integer)
    PlatformRefGUID = Column(Text)
    PlatformRelationship = Column(Text)
    PlatformSubjectID = Column(Integer)
    PlatformSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PLATFORMMAPPING {self.PlatformMappingID}>'

class PLATFORMSPECIFICATION(Base):
    __tablename__ = 'PLATFORMSPECIFICATION'
    __bind_key__  = 'XORCISM'

    PlatformSpecificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PLATFORMSPECIFICATION {self.PlatformSpecificationID}>'

class PLATFORMTAG(Base):
    __tablename__ = 'PLATFORMTAG'
    __bind_key__  = 'XORCISM'

    PlatformTagID = Column(Integer, primary_key=True)
    PlatformID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PLATFORMTAG {self.PlatformTagID}>'

class PLUGIN(Base):
    __tablename__ = 'PLUGIN'
    __bind_key__  = 'XORCISM'

    PluginID = Column(Integer, primary_key=True)
    PluginGUID = Column(Text)
    PluginName = Column(Text)
    PluginDescription = Column(Text)
    ModuleID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PLUGIN {self.PluginID}>'

class PLUGINPARAMETER(Base):
    __tablename__ = 'PLUGINPARAMETER'
    __bind_key__  = 'XORCISM'

    PluginParameterID = Column(Integer, primary_key=True)
    PluginID = Column(Integer, nullable=False)
    ParameterID = Column(Integer, nullable=False)
    ordinal_position = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PLUGINPARAMETER {self.PluginParameterID}>'

class PLUGINREFERENCE(Base):
    __tablename__ = 'PLUGINREFERENCE'
    __bind_key__  = 'XORCISM'

    PluginReferenceID = Column(Integer, primary_key=True)
    PluginID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)

    def __repr__(self):
        return f'<PLUGINREFERENCE {self.PluginReferenceID}>'

class PLUGINTAG(Base):
    __tablename__ = 'PLUGINTAG'
    __bind_key__  = 'XORCISM'

    PluginTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PLUGINTAG {self.PluginTagID}>'

class PLUGINVERSION(Base):
    __tablename__ = 'PLUGINVERSION'
    __bind_key__  = 'XORCISM'

    PluginVersionID = Column(Integer, primary_key=True)
    PluginID = Column(Integer, nullable=False)
    VersionID = Column(Integer, nullable=False)
    PluginVersionDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PLUGINVERSION {self.PluginVersionID}>'

class POLICY(Base):
    __tablename__ = 'POLICY'
    __bind_key__  = 'XORCISM'

    PolicyID = Column(Integer, primary_key=True)
    PolicyName = Column(Text)
    PolicyDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<POLICY {self.PolicyID}>'

class POLICYTERM(Base):
    __tablename__ = 'POLICYTERM'
    __bind_key__  = 'XORCISM'

    PolicyTermID = Column(Integer, primary_key=True)
    AcronymID = Column(Integer)
    PolicyTerm = Column(Text, nullable=False)
    PolicyTermDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<POLICYTERM {self.PolicyTermID}>'

class POLICYTERMFORPOLICY(Base):
    __tablename__ = 'POLICYTERMFORPOLICY'
    __bind_key__  = 'XORCISM'

    PolicyTermForPolicyID = Column(Integer, primary_key=True)
    PolicyID = Column(Integer, nullable=False)
    PolicyTermID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<POLICYTERMFORPOLICY {self.PolicyTermForPolicyID}>'

class PORT(Base):
    __tablename__ = 'PORT'
    __bind_key__  = 'XORCISM'

    PortID = Column(Integer, primary_key=True)
    Port_Value = Column(Integer, nullable=False)
    ProtocolID = Column(Integer)
    DefaultProtocolName = Column(Text)
    DefaultServiceName = Column(Text)
    PortName = Column(Text)
    PortDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PORT {self.PortID}>'

class PORTFOREXPLOIT(Base):
    __tablename__ = 'PORTFOREXPLOIT'
    __bind_key__  = 'XORCISM'

    ExploitPortID = Column(Integer, primary_key=True)
    ExploitID = Column(Integer, nullable=False)
    ExploitGUID = Column(Text)
    ExploitPortRelationship = Column(Text)
    PortID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<PORTFOREXPLOIT {self.ExploitPortID}>'

class PORTFORVULNERABILITY(Base):
    __tablename__ = 'PORTFORVULNERABILITY'
    __bind_key__  = 'XORCISM'

    VulnerabilityPortID = Column(Integer, primary_key=True)
    VulnerabilityID = Column(Integer, nullable=False)
    VulnerabilityGUID = Column(Text)
    VulnerabilityPortRelationship = Column(Text)
    PortID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<PORTFORVULNERABILITY {self.VulnerabilityPortID}>'

class POSSIBLERESTRICTION(Base):
    __tablename__ = 'POSSIBLERESTRICTION'
    __bind_key__  = 'XORCISM'

    PossibleRestrictionID = Column(Integer, primary_key=True)
    RestrictionHint = Column(Text, nullable=False)

    def __repr__(self):
        return f'<POSSIBLERESTRICTION {self.PossibleRestrictionID}>'

class POSTALADDRESS(Base):
    __tablename__ = 'POSTALADDRESS'
    __bind_key__  = 'XORCISM'

    PostalAddressID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<POSTALADDRESS {self.PostalAddressID}>'

class PREVALENCE(Base):
    __tablename__ = 'PREVALENCE'
    __bind_key__  = 'XORCISM'

    PrevalenceID = Column(Integer, primary_key=True)
    PrevalenceName = Column(Text, nullable=False)
    PrevalenceDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PREVALENCE {self.PrevalenceID}>'

class PRIORITYLEVEL(Base):
    __tablename__ = 'PRIORITYLEVEL'
    __bind_key__  = 'XORCISM'

    PriorityLevelID = Column(Integer, primary_key=True)
    PriorityLevelName = Column(Text)
    PriotityCode = Column(Text)
    Sequencing = Column(Text)
    PriorityLevelDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRIORITYLEVEL {self.PriorityLevelID}>'

class PRIVACYNOTIFICATION(Base):
    __tablename__ = 'PRIVACYNOTIFICATION'
    __bind_key__  = 'XORCISM'

    PrivacyNotificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PRIVACYNOTIFICATION {self.PrivacyNotificationID}>'

class PRIVACYRULE(Base):
    __tablename__ = 'PRIVACYRULE'
    __bind_key__  = 'XORCISM'

    PrivacyRuleID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PRIVACYRULE {self.PrivacyRuleID}>'

class PRIVILEGE(Base):
    __tablename__ = 'PRIVILEGE'
    __bind_key__  = 'XORCISM'

    PrivilegeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PRIVILEGE {self.PrivilegeID}>'

class PRIVILEGEESCALATIONPROPERTIES(Base):
    __tablename__ = 'PRIVILEGEESCALATIONPROPERTIES'
    __bind_key__  = 'XORCISM'

    PrivilegeEscalationPropertiesID = Column(Integer, primary_key=True)
    PrivilegeEscalationPropertiesName = Column(Text)
    PrivilegeEscalationPropertiesDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRIVILEGEESCALATIONPROPERTIES {self.PrivilegeEscalationPropertiesID}>'

class PRIVILEGEESCALATIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'PRIVILEGEESCALATIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    PrivilegeEscalationStrategicObjectiveID = Column(Integer, primary_key=True)
    PrivilegeEscalationStrategicObjectiveName = Column(Text)
    PrivilegeEscalationStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRIVILEGEESCALATIONSTRATEGICOBJECTIVE {self.PrivilegeEscalationStrategicObjectiveID}>'

class PRIVILEGEESCALATIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'PRIVILEGEESCALATIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    PrivilegeEscalationTacticalObjectiveID = Column(Integer, primary_key=True)
    PrivilegeEscalationTacticalObjectiveName = Column(Text)
    PrivilegeEscalationTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRIVILEGEESCALATIONTACTICALOBJECTIVE {self.PrivilegeEscalationTacticalObjectiveID}>'

class PRIVILEGESFORROLE(Base):
    __tablename__ = 'PRIVILEGESFORROLE'
    __bind_key__  = 'XORCISM'

    ID = Column(Integer, primary_key=True)
    RoleID = Column(Text)
    Responsible = Column(Integer)
    Accountable = Column(Integer)
    Consulted = Column(Integer)
    Informed = Column(Integer)

    def __repr__(self):
        return f'<PRIVILEGESFORROLE {self.ID}>'

class PROBINGSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'PROBINGSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    ProbingStrategicObjectiveID = Column(Integer, primary_key=True)
    ProbingStrategicObjectiveName = Column(Text)
    ProbingStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROBINGSTRATEGICOBJECTIVE {self.ProbingStrategicObjectiveID}>'

class PROBINGTACTICALOBJECTIVE(Base):
    __tablename__ = 'PROBINGTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    ProbingTacticalObjectiveID = Column(Integer, primary_key=True)
    ProbingTacticalObjectiveName = Column(Text)
    ProbingTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROBINGTACTICALOBJECTIVE {self.ProbingTacticalObjectiveID}>'

class PROBINGTECHNIQUE(Base):
    __tablename__ = 'PROBINGTECHNIQUE'
    __bind_key__  = 'XORCISM'

    ProbingTechniqueID = Column(Integer, primary_key=True)
    ProbingTechniqueGUID = Column(Text)
    TechniqueID = Column(Integer)
    ProbingTechniqueName = Column(Text)
    ProbingTechniqueDescription = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROBINGTECHNIQUE {self.ProbingTechniqueID}>'

class PROBINGTECHNIQUEFORATTACKPATTERN(Base):
    __tablename__ = 'PROBINGTECHNIQUEFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternProbingTechniqueID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer, nullable=False)
    capec_id = Column(Text)
    ProbingTechniqueID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PROBINGTECHNIQUEFORATTACKPATTERN {self.AttackPatternProbingTechniqueID}>'

class PROCEDURE(Base):
    __tablename__ = 'PROCEDURE'
    __bind_key__  = 'XORCISM'

    ProcedureID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PROCEDURE {self.ProcedureID}>'

class PROCESS(Base):
    __tablename__ = 'PROCESS'
    __bind_key__  = 'XORCISM'

    ProcessID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PROCESS {self.ProcessID}>'

class PROCESSACTIONNAME(Base):
    __tablename__ = 'PROCESSACTIONNAME'
    __bind_key__  = 'XORCISM'

    ProcessActionNameID = Column(Integer, primary_key=True)
    ProcessActionNameName = Column(Text, nullable=False)
    ProcessActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PROCESSACTIONNAME {self.ProcessActionNameID}>'

class PROCESSMEMORYACTIONNAME(Base):
    __tablename__ = 'PROCESSMEMORYACTIONNAME'
    __bind_key__  = 'XORCISM'

    ProcessMemoryActionNameID = Column(Integer, primary_key=True)
    ProcessMemoryActionNameName = Column(Text, nullable=False)
    ProcessMemoryActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PROCESSMEMORYACTIONNAME {self.ProcessMemoryActionNameID}>'

class PROCESSORTYPE(Base):
    __tablename__ = 'PROCESSORTYPE'
    __bind_key__  = 'XORCISM'

    ProcessorTypeID = Column(Integer, primary_key=True)
    ProcessorTypeName = Column(Text, nullable=False)
    ProcessorTypeDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PROCESSORTYPE {self.ProcessorTypeID}>'

class PROCESSORTYPEMAPPING(Base):
    __tablename__ = 'PROCESSORTYPEMAPPING'
    __bind_key__  = 'XORCISM'

    ProcessorTypeMappingID = Column(Integer, primary_key=True)
    ProcessorTypeRefID = Column(Integer, nullable=False)
    ProcessorTypeSubjectID = Column(Integer, nullable=False)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROCESSORTYPEMAPPING {self.ProcessorTypeMappingID}>'

class PROCESSORTYPEREGISTER(Base):
    __tablename__ = 'PROCESSORTYPEREGISTER'
    __bind_key__  = 'XORCISM'

    ProcessorTypeID = Column(Integer, primary_key=True)
    RegisterID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<PROCESSORTYPEREGISTER {self.ProcessorTypeID}>'

class PROCESSTHREADACTIONNAME(Base):
    __tablename__ = 'PROCESSTHREADACTIONNAME'
    __bind_key__  = 'XORCISM'

    ProcessThreadActionNameID = Column(Integer, primary_key=True)
    ProcessThreadActionNameName = Column(Text, nullable=False)
    ProcessThreadActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PROCESSTHREADACTIONNAME {self.ProcessThreadActionNameID}>'

class PRODUCT(Base):
    __tablename__ = 'PRODUCT'
    __bind_key__  = 'XORCISM'

    ProductID = Column(Integer, primary_key=True)
    ProductGUID = Column(Text)
    ProductName = Column(Text)
    ProductVendor = Column(Text)
    OrganisationID = Column(Integer)
    CPEName = Column(Text)
    ProductEdition = Column(Text)
    ProductUpdate = Column(Text)
    ProductVersion = Column(Text)
    CPEID = Column(Integer)
    ProductLanguage = Column(Text)
    LocaleID = Column(Integer)
    DeviceID = Column(Integer)
    CreatedDate = Column(Text)
    ProductDescription = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRODUCT {self.ProductID}>'

class PRODUCTCATEGORY(Base):
    __tablename__ = 'PRODUCTCATEGORY'
    __bind_key__  = 'XORCISM'

    ProductCategoryID = Column(Integer, primary_key=True)
    ProductCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    ProductCategoryName = Column(Text)
    ProductCategoryShortName = Column(Text)
    ProductCategoryDescription = Column(Text)
    OrganisationID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTCATEGORY {self.ProductCategoryID}>'

class PRODUCTCATEGORYFORPRODUCT(Base):
    __tablename__ = 'PRODUCTCATEGORYFORPRODUCT'
    __bind_key__  = 'XORCISM'

    ProductCategoryForProductID = Column(Integer, primary_key=True)
    ProductID = Column(Integer, nullable=False)
    ProductGUID = Column(Text)
    ProductCategoryID = Column(Integer, nullable=False)
    ProductCategoryGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTCATEGORYFORPRODUCT {self.ProductCategoryForProductID}>'

class PRODUCTEXPLOIT(Base):
    __tablename__ = 'PRODUCTEXPLOIT'
    __bind_key__  = 'XORCISM'

    ProductExploitID = Column(Integer, primary_key=True)
    ProductID = Column(Integer)
    ProductGUID = Column(Text)
    ExploitID = Column(Integer)
    ExploitGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTEXPLOIT {self.ProductExploitID}>'

class PRODUCTFILE(Base):
    __tablename__ = 'PRODUCTFILE'
    __bind_key__  = 'XORCISM'

    ProductFileID = Column(Integer, primary_key=True)
    ProductID = Column(Integer)
    ProductFileRelationship = Column(Text)
    ProductFileDescription = Column(Text)
    FileID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTFILE {self.ProductFileID}>'

class PRODUCTFILELIST(Base):
    __tablename__ = 'PRODUCTFILELIST'
    __bind_key__  = 'XORCISM'

    ProductFileListID = Column(Integer, primary_key=True)
    ProductID = Column(Integer)
    ProductGUID = Column(Text)
    ProductFileListRelationship = Column(Text)
    ProductFileListDescription = Column(Text)
    FileListID = Column(Integer)
    FileListGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTFILELIST {self.ProductFileListID}>'

class PRODUCTMAPPING(Base):
    __tablename__ = 'PRODUCTMAPPING'
    __bind_key__  = 'XORCISM'

    ProductMappingID = Column(Integer, primary_key=True)
    ProductRefID = Column(Integer)
    ProductRefGUID = Column(Text)
    ProductRelationship = Column(Text)
    ProductMappingDescription = Column(Text)
    ProductSubjectID = Column(Integer)
    ProductSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTMAPPING {self.ProductMappingID}>'

class PRODUCTPATCH(Base):
    __tablename__ = 'PRODUCTPATCH'
    __bind_key__  = 'XORCISM'

    ProductPatchID = Column(Integer, primary_key=True)
    ProductID = Column(Integer)
    ProductGUID = Column(Text)
    ProductPatchRelationship = Column(Text)
    ProductPatchDescription = Column(Text)
    PatchID = Column(Integer)
    PatchGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTPATCH {self.ProductPatchID}>'

class PRODUCTPLATFORM(Base):
    __tablename__ = 'PRODUCTPLATFORM'
    __bind_key__  = 'XORCISM'

    ProductPlaformID = Column(Integer, primary_key=True)
    ProductID = Column(Integer)
    ProductGUID = Column(Text)
    ProductPlatformRelationship = Column(Text)
    PlatformID = Column(Integer)
    PlatformGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromdate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTPLATFORM {self.ProductPlaformID}>'

class PRODUCTPORT(Base):
    __tablename__ = 'PRODUCTPORT'
    __bind_key__  = 'XORCISM'

    ProductPortID = Column(Integer, primary_key=True)
    ProductID = Column(Integer)
    ProductGUID = Column(Text)
    ProductPortRelationship = Column(Text)
    PortID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTPORT {self.ProductPortID}>'

class PRODUCTTAG(Base):
    __tablename__ = 'PRODUCTTAG'
    __bind_key__  = 'XORCISM'

    ProductTagID = Column(Integer, primary_key=True)
    ProductID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PRODUCTTAG {self.ProductTagID}>'

class PROJECT(Base):
    __tablename__ = 'PROJECT'
    __bind_key__  = 'XORCISM'

    ProjectID = Column(Integer, primary_key=True)
    ProjectGUID = Column(Text)
    ProjectName = Column(Text, nullable=False)
    ProjectDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ExpectedCompletionDate = Column(Text)
    DueDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)
    ConfidentialityLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    ImportanceID = Column(Integer)

    def __repr__(self):
        return f'<PROJECT {self.ProjectID}>'

class PROJECTDESCRIPTION(Base):
    __tablename__ = 'PROJECTDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ProjectDescriptionID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer)
    ProjectGUID = Column(Text)
    DescriptionID = Column(Integer)
    DescriptionGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROJECTDESCRIPTION {self.ProjectDescriptionID}>'

class PROJECTFINDING(Base):
    __tablename__ = 'PROJECTFINDING'
    __bind_key__  = 'XORCISM'

    ProjectFindingID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer)
    ProjectGUID = Column(Text)
    FindingID = Column(Integer)
    FindingGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PROJECTFINDING {self.ProjectFindingID}>'

class PROJECTFORAPPLICATION(Base):
    __tablename__ = 'PROJECTFORAPPLICATION'
    __bind_key__  = 'XORCISM'

    ProjectApplicationID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer, nullable=False)
    ProjectGUID = Column(Text)
    ApplicationID = Column(Integer, nullable=False)
    ApplicationGUID = Column(Text)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    ProjectDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    OrganisationID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PROJECTFORAPPLICATION {self.ProjectApplicationID}>'

class PROJECTMAPPING(Base):
    __tablename__ = 'PROJECTMAPPING'
    __bind_key__  = 'XORCISM'

    ProjectMappingID = Column(Integer, primary_key=True)
    ProjectRefID = Column(Integer)
    ProjectRefGUID = Column(Text)
    ProjectRelationship = Column(Text)
    ProjectMappingDescription = Column(Text)
    ProjectSubjectID = Column(Integer)
    ProjectSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROJECTMAPPING {self.ProjectMappingID}>'

class PROJECTMETHODOLOGY(Base):
    __tablename__ = 'PROJECTMETHODOLOGY'
    __bind_key__  = 'XORCISM'

    ProjectMethodologyID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer, nullable=False)
    ProjectGUID = Column(Text)
    MethodologyID = Column(Integer, nullable=False)
    MethodologyGUID = Column(Text)
    PersonID = Column(Integer)
    PersonGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ProjectMethodologyDescription = Column(Text, nullable=False)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PROJECTMETHODOLOGY {self.ProjectMethodologyID}>'

class PROJECTPERSON(Base):
    __tablename__ = 'PROJECTPERSON'
    __bind_key__  = 'XORCISM'

    ProjectPersonID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer, nullable=False)
    ProjectGUID = Column(Text)
    PersonID = Column(Integer, nullable=False)
    PersonGUID = Column(Text)
    ProjectPersonRole = Column(Text)
    ProjectPersonDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PROJECTPERSON {self.ProjectPersonID}>'

class PROJECTTAG(Base):
    __tablename__ = 'PROJECTTAG'
    __bind_key__  = 'XORCISM'

    ProjectTagID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer)
    ProjectGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROJECTTAG {self.ProjectTagID}>'

class PROJECTTASK(Base):
    __tablename__ = 'PROJECTTASK'
    __bind_key__  = 'XORCISM'

    ProjectTaskID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer, nullable=False)
    ProjectGUID = Column(Text)
    TaskID = Column(Integer, nullable=False)
    TaskGUID = Column(Text)
    CreatedDate = Column(Text)
    ProjectTaskName = Column(Text)
    ProjectTaskDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<PROJECTTASK {self.ProjectTaskID}>'

class PROJECTTASKFINDING(Base):
    __tablename__ = 'PROJECTTASKFINDING'
    __bind_key__  = 'XORCISM'

    ProjectTaskFindingID = Column(Integer, primary_key=True)
    ProjectTaskID = Column(Integer)
    ProjectTaskGUID = Column(Text)
    FindingID = Column(Integer)
    FindingGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROJECTTASKFINDING {self.ProjectTaskFindingID}>'

class PROJECTTASKPERSON(Base):
    __tablename__ = 'PROJECTTASKPERSON'
    __bind_key__  = 'XORCISM'

    ProjectTaskPersonID = Column(Integer, primary_key=True)
    ProjectTaskID = Column(Integer, nullable=False)
    ProjectTaskGUID = Column(Text)
    PersonID = Column(Integer, nullable=False)
    PersonGUID = Column(Text)
    CreatedDate = Column(Text)
    ProjectTaskPersonRole = Column(Text)
    ProjectTaskDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROJECTTASKPERSON {self.ProjectTaskPersonID}>'

class PROJECTTECHNIQUE(Base):
    __tablename__ = 'PROJECTTECHNIQUE'
    __bind_key__  = 'XORCISM'

    ProjectTechniqueID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PROJECTTECHNIQUE {self.ProjectTechniqueID}>'

class PROPERTYTYPE(Base):
    __tablename__ = 'PROPERTYTYPE'
    __bind_key__  = 'XORCISM'

    PropertyTypeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<PROPERTYTYPE {self.PropertyTypeID}>'

class PROTOCOL(Base):
    __tablename__ = 'PROTOCOL'
    __bind_key__  = 'XORCISM'

    ProtocolID = Column(Integer, primary_key=True)
    ProtocolAbbreviation = Column(Text)
    ProtocolName = Column(Text, nullable=False)
    ProtocolDescription = Column(Text)
    ProtocolRFC = Column(Text)
    ProtocolBAF = Column(Text)
    VocabularyID = Column(Integer)
    OSILayerID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<PROTOCOL {self.ProtocolID}>'

class PROTOCOLCOMMAND(Base):
    __tablename__ = 'PROTOCOLCOMMAND'
    __bind_key__  = 'XORCISM'

    ProtocolCommandID = Column(Integer, primary_key=True)
    ProtocolID = Column(Integer)
    CommandID = Column(Integer)
    KnownVulnerable = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROTOCOLCOMMAND {self.ProtocolCommandID}>'

class PROTOCOLFORPROTOCOL(Base):
    __tablename__ = 'PROTOCOLFORPROTOCOL'
    __bind_key__  = 'XORCISM'

    ProtocolRelationshipID = Column(Integer, primary_key=True)
    ProtocolRefID = Column(Integer, nullable=False)
    ProtocolRelationshipName = Column(Text)
    ProtocolSubjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROTOCOLFORPROTOCOL {self.ProtocolRelationshipID}>'

class PROTOCOLHEADER(Base):
    __tablename__ = 'PROTOCOLHEADER'
    __bind_key__  = 'XORCISM'

    ProtocolHeaderID = Column(Integer, primary_key=True)
    ProtocolHeaderGUID = Column(Text)
    Protocol_Field_Name = Column(Text)
    Protocol_Field_Description = Column(Text)
    Protocol_Operation_Code = Column(Text)
    Protocol_Data = Column(Text)
    Protocol_Flag_Value = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROTOCOLHEADER {self.ProtocolHeaderID}>'

class PROTOCOLREFERENCE(Base):
    __tablename__ = 'PROTOCOLREFERENCE'
    __bind_key__  = 'XORCISM'

    ProtocolReferenceID = Column(Integer, primary_key=True)
    ProtocolID = Column(Integer)
    ReferenceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROTOCOLREFERENCE {self.ProtocolReferenceID}>'

class PROVIDER(Base):
    __tablename__ = 'PROVIDER'
    __bind_key__  = 'XORCISM'

    ProviderID = Column(Integer, primary_key=True)
    ProviderGUID = Column(Text)
    ProviderName = Column(Text)
    PluginReference = Column(Text)
    ServiceCategoryID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<PROVIDER {self.ProviderID}>'

class PROVIDERSFORACCOUNT(Base):
    __tablename__ = 'PROVIDERSFORACCOUNT'
    __bind_key__  = 'XORCISM'

    ProviderAccountID = Column(Integer, primary_key=True)
    ProviderID = Column(Integer)
    AccountID = Column(Integer)
    ValidUntil = Column(Text)

    def __repr__(self):
        return f'<PROVIDERSFORACCOUNT {self.ProviderAccountID}>'

class RACIMATRIX(Base):
    __tablename__ = 'RACIMATRIX'
    __bind_key__  = 'XORCISM'

    RACIMatrixID = Column(Integer, primary_key=True)
    TaskType = Column(Text)
    TaskID = Column(Text)
    RACIResponsability = Column(Text)
    UserID = Column(Text)
    AccountID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RACIMATRIX {self.RACIMatrixID}>'

class RACITASK(Base):
    __tablename__ = 'RACITASK'
    __bind_key__  = 'XORCISM'

    RACITaskID = Column(Integer, primary_key=True)
    TaskType = Column(Text)
    RACIResponsability = Column(Text)
    UserID = Column(Text)
    AccountID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RACITASK {self.RACITaskID}>'

class RATEFILTER(Base):
    __tablename__ = 'RATEFILTER'
    __bind_key__  = 'XORCISM'

    RateFilterID = Column(Integer, primary_key=True)
    RateFilterContent = Column(Text)
    RateFilterDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RATEFILTER {self.RateFilterID}>'

class RAWARTIFACT(Base):
    __tablename__ = 'RAWARTIFACT'
    __bind_key__  = 'XORCISM'

    RawArtifactID = Column(Integer, primary_key=True)
    RawArtifactGUID = Column(Text)
    byte_order = Column(Text)
    is_encrypted = Column(Integer)
    is_compressed = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    CollectionMethodID = Column(Integer)
    SourceID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RAWARTIFACT {self.RawArtifactID}>'

class RAWARTIFACTDESCRIPTION(Base):
    __tablename__ = 'RAWARTIFACTDESCRIPTION'
    __bind_key__  = 'XORCISM'

    RawArtifactDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<RAWARTIFACTDESCRIPTION {self.RawArtifactDescriptionID}>'

class RAWARTIFACTTAG(Base):
    __tablename__ = 'RAWARTIFACTTAG'
    __bind_key__  = 'XORCISM'

    RawArtifactTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<RAWARTIFACTTAG {self.RawArtifactTagID}>'

class REASON(Base):
    __tablename__ = 'REASON'
    __bind_key__  = 'XORCISM'

    ReasonID = Column(Integer, primary_key=True)
    ReasonGUID = Column(Text)
    ReasonName = Column(Text)
    ReasonDescription = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<REASON {self.ReasonID}>'

class RECOMMENDATION(Base):
    __tablename__ = 'RECOMMENDATION'
    __bind_key__  = 'XORCISM'

    RecommendationID = Column(Integer, primary_key=True)
    RecommendationGUID = Column(Text)
    RecommendationVocabularyID = Column(Text)
    RecommendationName = Column(Text)
    RecommendationLevel = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    RecommendationDescription = Column(Text)
    RecommendationRationale = Column(Text)
    RemediationProcedure = Column(Text)
    RecommendationImpact = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    StatusID = Column(Integer)
    ScoringStatusID = Column(Integer)
    LocaleID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RECOMMENDATION {self.RecommendationID}>'

class RECOMMENDATIONAUDITPROCEDURE(Base):
    __tablename__ = 'RECOMMENDATIONAUDITPROCEDURE'
    __bind_key__  = 'XORCISM'

    RecommendationAuditProcedureID = Column(Integer, primary_key=True)
    RecommendationID = Column(Integer, nullable=False)
    AuditProcedureID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    RecommendationAuditProcedureName = Column(Text)
    RecommendationAuditProcedureDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<RECOMMENDATIONAUDITPROCEDURE {self.RecommendationAuditProcedureID}>'

class RECOMMENDATIONCCE(Base):
    __tablename__ = 'RECOMMENDATIONCCE'
    __bind_key__  = 'XORCISM'

    RecommendationCCEID = Column(Integer, primary_key=True)
    RecommendationID = Column(Integer, nullable=False)
    RecommendationGUID = Column(Text)
    CCEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RECOMMENDATIONCCE {self.RecommendationCCEID}>'

class RECOMMENDATIONTAG(Base):
    __tablename__ = 'RECOMMENDATIONTAG'
    __bind_key__  = 'XORCISM'

    RecommendationTagID = Column(Integer, primary_key=True)
    RecommendationID = Column(Integer, nullable=False)
    RecommendationGUID = Column(Text)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RECOMMENDATIONTAG {self.RecommendationTagID}>'

class RECOMMENDATIONTIP(Base):
    __tablename__ = 'RECOMMENDATIONTIP'
    __bind_key__  = 'XORCISM'

    RecommendationTipID = Column(Integer, primary_key=True)
    RecommendationTypeGUID = Column(Text)
    RecommendationID = Column(Integer)
    RecommendationGUID = Column(Text)
    TipID = Column(Integer)
    TipGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<RECOMMENDATIONTIP {self.RecommendationTipID}>'

class REFERENCE(Base):
    __tablename__ = 'REFERENCE'
    __bind_key__  = 'XORCISM'

    ReferenceID = Column(Integer, primary_key=True)
    ReferenceGUID = Column(Text)
    ReferenceSourceID = Column(Text)
    Source = Column(Text)
    SourceTrustLevelID = Column(Integer)
    SourceTrustReasonID = Column(Integer)
    ReferenceTitle = Column(Text)
    ReferenceDescription = Column(Text)
    Type = Column(Text)
    ReferenceCategoryID = Column(Integer)
    ReferenceURL = Column(Text)
    ReferenceFilePath = Column(Text)
    lang = Column(Text)
    LocaleID = Column(Integer)
    notes = Column(Text)
    ReferenceVersion = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    LastCheckedDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    Reference_Publication = Column(Text)
    Reference_Edition = Column(Text)
    Reference_PubDate = Column(Text)
    Reference_Publisher = Column(Text)
    ReferenceISBN = Column(Text)
    Reference_Date = Column(Text)

    def __repr__(self):
        return f'<REFERENCE {self.ReferenceID}>'

class REFERENCEAUTHOR(Base):
    __tablename__ = 'REFERENCEAUTHOR'
    __bind_key__  = 'XORCISM'

    ReferenceAuthorID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer, nullable=False)
    AuthorID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<REFERENCEAUTHOR {self.ReferenceAuthorID}>'

class REFERENCECATEGORY(Base):
    __tablename__ = 'REFERENCECATEGORY'
    __bind_key__  = 'XORCISM'

    ReferenceCategoryID = Column(Integer, primary_key=True)
    ReferenceCategoryGUID = Column(Text)
    CategoryID = Column(Integer, nullable=False)
    ReferenceCategoryName = Column(Text)
    ReferenceCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<REFERENCECATEGORY {self.ReferenceCategoryID}>'

class REFERENCECATEGORYTAG(Base):
    __tablename__ = 'REFERENCECATEGORYTAG'
    __bind_key__  = 'XORCISM'

    ReferenceCategoryTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<REFERENCECATEGORYTAG {self.ReferenceCategoryTagID}>'

class REFERENCECHANGERECORD(Base):
    __tablename__ = 'REFERENCECHANGERECORD'
    __bind_key__  = 'XORCISM'

    ReferenceChangeRecordID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    ChangeRecordID = Column(Integer, nullable=False)
    ChangeRecordGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REFERENCECHANGERECORD {self.ReferenceChangeRecordID}>'

class REFERENCEDESCRIPTION(Base):
    __tablename__ = 'REFERENCEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ReferenceDescriptionID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REFERENCEDESCRIPTION {self.ReferenceDescriptionID}>'

class REFERENCEMAPPING(Base):
    __tablename__ = 'REFERENCEMAPPING'
    __bind_key__  = 'XORCISM'

    ReferenceMappingID = Column(Integer, primary_key=True)
    ReferenceRefID = Column(Integer)
    RelationShipText = Column(Text)
    ReferenceSubjectID = Column(Integer)
    ReferenceMappingDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REFERENCEMAPPING {self.ReferenceMappingID}>'

class REFERENCETAG(Base):
    __tablename__ = 'REFERENCETAG'
    __bind_key__  = 'XORCISM'

    ReferenceTagID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REFERENCETAG {self.ReferenceTagID}>'

class REGEX(Base):
    __tablename__ = 'REGEX'
    __bind_key__  = 'XORCISM'

    RegexID = Column(Integer, primary_key=True)
    RegularExpression = Column(Text)
    RegexDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<REGEX {self.RegexID}>'

class REGEXCAPTUREFUNCTION(Base):
    __tablename__ = 'REGEXCAPTUREFUNCTION'
    __bind_key__  = 'XORCISM'

    RegexCaptureFunctionID = Column(Integer, primary_key=True)
    Regex = Column(Text, nullable=False)
    OVALComponentGroupID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<REGEXCAPTUREFUNCTION {self.RegexCaptureFunctionID}>'

class REGEXLANGUAGE(Base):
    __tablename__ = 'REGEXLANGUAGE'
    __bind_key__  = 'XORCISM'

    RegexLanguageID = Column(Integer, primary_key=True)
    RegexID = Column(Integer, nullable=False)
    LanguageID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<REGEXLANGUAGE {self.RegexLanguageID}>'

class REGEXREFERENCE(Base):
    __tablename__ = 'REGEXREFERENCE'
    __bind_key__  = 'XORCISM'

    RegexReferenceID = Column(Integer, primary_key=True)
    RegexID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<REGEXREFERENCE {self.RegexReferenceID}>'

class REGISTER(Base):
    __tablename__ = 'REGISTER'
    __bind_key__  = 'XORCISM'

    RegisterID = Column(Integer, primary_key=True)
    RegisterName = Column(Text, nullable=False)
    RegisterDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<REGISTER {self.RegisterID}>'

class REGISTRYACTIONNAME(Base):
    __tablename__ = 'REGISTRYACTIONNAME'
    __bind_key__  = 'XORCISM'

    RegistryActionNameID = Column(Integer, primary_key=True)
    RegistryActionNameName = Column(Text, nullable=False)
    RegistryActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<REGISTRYACTIONNAME {self.RegistryActionNameID}>'

class REGISTRYDATATYPE(Base):
    __tablename__ = 'REGISTRYDATATYPE'
    __bind_key__  = 'XORCISM'

    RegistryDatatypeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<REGISTRYDATATYPE {self.RegistryDatatypeID}>'

class REGISTRYDATATYPEREFERENCE(Base):
    __tablename__ = 'REGISTRYDATATYPEREFERENCE'
    __bind_key__  = 'XORCISM'

    RegistryDatatypeReferenceID = Column(Integer, primary_key=True)
    RegistryDatatypeID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REGISTRYDATATYPEREFERENCE {self.RegistryDatatypeReferenceID}>'

class REGISTRYDATATYPESENUM(Base):
    __tablename__ = 'REGISTRYDATATYPESENUM'
    __bind_key__  = 'XORCISM'

    RegistryDatatypesEnumID = Column(Integer, primary_key=True)
    RegistryDatatypeName = Column(Text, nullable=False)
    RegistryDatatypeDescription = Column(Text)
    RegistryDatatypeReference = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REGISTRYDATATYPESENUM {self.RegistryDatatypesEnumID}>'

class REGISTRYHIVEENUM(Base):
    __tablename__ = 'REGISTRYHIVEENUM'
    __bind_key__  = 'XORCISM'

    RegistryHiveEnumID = Column(Integer, primary_key=True)
    RegistryHiveName = Column(Text, nullable=False)
    RegistryHiveDescription = Column(Text)
    RegistryHiveReference = Column(Text)
    ReferenceID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REGISTRYHIVEENUM {self.RegistryHiveEnumID}>'

class REGISTRYSUBKEYS(Base):
    __tablename__ = 'REGISTRYSUBKEYS'
    __bind_key__  = 'XORCISM'

    RegistrySubkeysID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<REGISTRYSUBKEYS {self.RegistrySubkeysID}>'

class REGISTRYSUBKEYSKEYS(Base):
    __tablename__ = 'REGISTRYSUBKEYSKEYS'
    __bind_key__  = 'XORCISM'

    RegistrySubkeysKeysID = Column(Integer, primary_key=True)
    RegistrySubkeysID = Column(Integer, nullable=False)
    WindowsRegistryKeyObjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<REGISTRYSUBKEYSKEYS {self.RegistrySubkeysKeysID}>'

class REGISTRYVALUE(Base):
    __tablename__ = 'REGISTRYVALUE'
    __bind_key__  = 'XORCISM'

    RegistryValueID = Column(Integer, primary_key=True)
    Name = Column(Text)
    Data = Column(Text)
    RegistryDatatypeID = Column(Integer)
    ByteRunsID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<REGISTRYVALUE {self.RegistryValueID}>'

class REGISTRYVALUES(Base):
    __tablename__ = 'REGISTRYVALUES'
    __bind_key__  = 'XORCISM'

    RegistryValuesID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REGISTRYVALUES {self.RegistryValuesID}>'

class REGISTRYVALUESREGISTRYVALUE(Base):
    __tablename__ = 'REGISTRYVALUESREGISTRYVALUE'
    __bind_key__  = 'XORCISM'

    RegistryValuesRegistryValueID = Column(Integer, primary_key=True)
    RegistryValuesID = Column(Integer, nullable=False)
    RegistryValueID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<REGISTRYVALUESREGISTRYVALUE {self.RegistryValuesRegistryValueID}>'

class REGULAREXPRESSION(Base):
    __tablename__ = 'REGULAREXPRESSION'
    __bind_key__  = 'XORCISM'

    RegularExpressionID = Column(Integer, primary_key=True)
    RegexID = Column(Integer)

    def __repr__(self):
        return f'<REGULAREXPRESSION {self.RegularExpressionID}>'

class REGULATORYRISK(Base):
    __tablename__ = 'REGULATORYRISK'
    __bind_key__  = 'XORCISM'

    RegulatoryRiskID = Column(Integer, primary_key=True)
    RegulatoryRiskGUID = Column(Text)
    RiskDescription = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REGULATORYRISK {self.RegulatoryRiskID}>'

class RELATIONSHIPTYPE(Base):
    __tablename__ = 'RELATIONSHIPTYPE'
    __bind_key__  = 'XORCISM'

    RelationshipTypeID = Column(Integer, primary_key=True)
    RelationshipTypeTerm = Column(Text)
    RelationshipTypeDomain = Column(Text)
    RelationshipTypeRange = Column(Text)
    RelationshipTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<RELATIONSHIPTYPE {self.RelationshipTypeID}>'

class RELIABILITY(Base):
    __tablename__ = 'RELIABILITY'
    __bind_key__  = 'XORCISM'

    ReliabilityID = Column(Integer, primary_key=True)
    ReliabilityGUID = Column(Text)
    ReliabilityName = Column(Text)
    ReliabilityDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<RELIABILITY {self.ReliabilityID}>'

class RELIABILITYREASON(Base):
    __tablename__ = 'RELIABILITYREASON'
    __bind_key__  = 'XORCISM'

    ReliabilityReasonID = Column(Integer, primary_key=True)
    ReliabilityReasonGUID = Column(Text)
    ReasonID = Column(Integer)
    ReasonGUID = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<RELIABILITYREASON {self.ReliabilityReasonID}>'

class REMOTEMACHINEMANIPULATIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'REMOTEMACHINEMANIPULATIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    RemoteMachineManipulationStrategicObjectiveID = Column(Integer, primary_key=True)
    RemoteMachineManipulationStrategicObjectiveName = Column(Text)
    RemoteMachineManipulationStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REMOTEMACHINEMANIPULATIONSTRATEGICOBJECTIVE {self.RemoteMachineManipulationStrategicObjectiveID}>'

class REMOTEMACHINEMANIPULATIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'REMOTEMACHINEMANIPULATIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    RemoteMachineManipulationTacticalObjectiveID = Column(Integer, primary_key=True)
    RemoteMachineManipulationTacticalObjectiveName = Column(Text)
    RemoteMachineManipulationTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REMOTEMACHINEMANIPULATIONTACTICALOBJECTIVE {self.RemoteMachineManipulationTacticalObjectiveID}>'

class REPORT(Base):
    __tablename__ = 'REPORT'
    __bind_key__  = 'XORCISM'

    ReportID = Column(Integer, primary_key=True)
    ReportGUID = Column(Text)
    ReportContent = Column(Text)
    ReferenceID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<REPORT {self.ReportID}>'

class REPORTFORREPORTS(Base):
    __tablename__ = 'REPORTFORREPORTS'
    __bind_key__  = 'XORCISM'

    ReportsID = Column(Integer, primary_key=True)
    ReportID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<REPORTFORREPORTS {self.ReportsID}>'

class REPORTREQUEST(Base):
    __tablename__ = 'REPORTREQUEST'
    __bind_key__  = 'XORCISM'

    ReportRequestID = Column(Integer, primary_key=True)
    ARFReportRequestID = Column(Text, nullable=False)
    ReportRequestContent = Column(Text)
    ReferenceID = Column(Integer)

    def __repr__(self):
        return f'<REPORTREQUEST {self.ReportRequestID}>'

class REPORTREQUESTFORREPORTREQUESTS(Base):
    __tablename__ = 'REPORTREQUESTFORREPORTREQUESTS'
    __bind_key__  = 'XORCISM'

    ReportRequestsID = Column(Integer, primary_key=True)
    ReportRequestID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<REPORTREQUESTFORREPORTREQUESTS {self.ReportRequestsID}>'

class REPORTREQUESTS(Base):
    __tablename__ = 'REPORTREQUESTS'
    __bind_key__  = 'XORCISM'

    ReportRequestsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<REPORTREQUESTS {self.ReportRequestsID}>'

class REPORTS(Base):
    __tablename__ = 'REPORTS'
    __bind_key__  = 'XORCISM'

    ReportsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<REPORTS {self.ReportsID}>'

class REPOSITORY(Base):
    __tablename__ = 'REPOSITORY'
    __bind_key__  = 'XORCISM'

    RepositoryID = Column(Integer, primary_key=True)
    RepositoryGUID = Column(Text)
    RepositoryName = Column(Text)
    RepositoryDescription = Column(Text)
    RepositoryURL = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<REPOSITORY {self.RepositoryID}>'

class REPOSITORYRESTRICTION(Base):
    __tablename__ = 'REPOSITORYRESTRICTION'
    __bind_key__  = 'XORCISM'

    RepositoryRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<REPOSITORYRESTRICTION {self.RepositoryRestrictionID}>'

class REPUTATION(Base):
    __tablename__ = 'REPUTATION'
    __bind_key__  = 'XORCISM'

    ReputationID = Column(Integer, primary_key=True)
    ReputationGUID = Column(Text)
    ReputationTitle = Column(Text)
    ReputationDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REPUTATION {self.ReputationID}>'

class REQUIREMENT(Base):
    __tablename__ = 'REQUIREMENT'
    __bind_key__  = 'XORCISM'

    RequirementID = Column(Integer, primary_key=True)
    RequirementGUID = Column(Text)
    RequirementTitle = Column(Text)
    RequirementDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<REQUIREMENT {self.RequirementID}>'

class REQUIREMENTCATEGORY(Base):
    __tablename__ = 'REQUIREMENTCATEGORY'
    __bind_key__  = 'XORCISM'

    RequirementCategoryID = Column(Integer, primary_key=True)
    RequirementID = Column(Integer)
    CategoryID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<REQUIREMENTCATEGORY {self.RequirementCategoryID}>'

class REQUIREMENTDESCRIPTION(Base):
    __tablename__ = 'REQUIREMENTDESCRIPTION'
    __bind_key__  = 'XORCISM'

    RequirementDescriptionID = Column(Integer, primary_key=True)
    RequirementID = Column(Integer)
    DescriptionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<REQUIREMENTDESCRIPTION {self.RequirementDescriptionID}>'

class REQUIREMENTMAPPING(Base):
    __tablename__ = 'REQUIREMENTMAPPING'
    __bind_key__  = 'XORCISM'

    RequirementMappingID = Column(Integer, primary_key=True)
    RequirementRefID = Column(Integer)
    RequirementRefGUID = Column(Text)
    RequirementSubjectID = Column(Integer)
    RequirementSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<REQUIREMENTMAPPING {self.RequirementMappingID}>'

class RESTRICTION(Base):
    __tablename__ = 'RESTRICTION'
    __bind_key__  = 'XORCISM'

    RestrictionID = Column(Integer, primary_key=True)
    OperationEnumerationValue = Column(Text, nullable=False)
    VariableValue = Column(Text, nullable=False)

    def __repr__(self):
        return f'<RESTRICTION {self.RestrictionID}>'

class RESULTENUMERATION(Base):
    __tablename__ = 'RESULTENUMERATION'
    __bind_key__  = 'XORCISM'

    ResultEnumerationID = Column(Integer, primary_key=True)
    ResultEnumerationValue = Column(Text, nullable=False)
    ResultEnumerationDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<RESULTENUMERATION {self.ResultEnumerationID}>'

class RISKRATING(Base):
    __tablename__ = 'RISKRATING'
    __bind_key__  = 'XORCISM'

    RiskRatingID = Column(Integer, primary_key=True)
    RiskRatingGUID = Column(Text)
    RiskRatingName = Column(Text)
    RiskRatingDescription = Column(Text)
    MethodologyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RISKRATING {self.RiskRatingID}>'

class RISKSCORE(Base):
    __tablename__ = 'RISKSCORE'
    __bind_key__  = 'XORCISM'

    RiskScoreID = Column(Integer, primary_key=True)
    RiskScore = Column(Integer)
    Date = Column(Text)  # date (ISO 8601, like the other dates)
    TenantID = Column(Integer)  # multi-tenant partitioning (TENANT_SCOPED_TABLES on the TS side)
    ConfidenceLevel = Column(Integer)

    def __repr__(self):
        return f'<RISKSCORE {self.RiskScoreID}>'

class ROLE(Base):
    __tablename__ = 'ROLE'
    __bind_key__  = 'XORCISM'

    RoleID = Column(Integer, primary_key=True)
    RoleGUID = Column(Text)
    RoleName = Column(Text)
    RoleDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ROLE {self.RoleID}>'

class ROPCHAIN(Base):
    __tablename__ = 'ROPCHAIN'
    __bind_key__  = 'XORCISM'

    ROPChainID = Column(Integer, primary_key=True)
    ROPChainName = Column(Text, nullable=False)
    ROPChainDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ROPCHAIN {self.ROPChainID}>'

class ROPCHAININSTRUCTION(Base):
    __tablename__ = 'ROPCHAININSTRUCTION'
    __bind_key__  = 'XORCISM'

    ROPChainID = Column(Integer, primary_key=True)
    InstructionID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ROPCHAININSTRUCTION {self.ROPChainID}>'

class ROPCHAINREFERENCE(Base):
    __tablename__ = 'ROPCHAINREFERENCE'
    __bind_key__  = 'XORCISM'

    ROPChainID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ROPCHAINREFERENCE {self.ROPChainID}>'

class ROPGADGET(Base):
    __tablename__ = 'ROPGADGET'
    __bind_key__  = 'XORCISM'

    ROPGadgetID = Column(Integer, primary_key=True)
    ROPGadgetGUID = Column(Text)
    ROPGadgetName = Column(Text)
    ROPGadgetDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ReliabilityID = Column(Integer)

    def __repr__(self):
        return f'<ROPGADGET {self.ROPGadgetID}>'

class ROPGADGETFORROPCHAIN(Base):
    __tablename__ = 'ROPGADGETFORROPCHAIN'
    __bind_key__  = 'XORCISM'

    ROPChainID = Column(Integer, primary_key=True)
    ROPGadgetID = Column(Integer, nullable=False)
    ROPGadgetOrder = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ROPGADGETFORROPCHAIN {self.ROPChainID}>'

class ROPGADGETINSTRUCTION(Base):
    __tablename__ = 'ROPGADGETINSTRUCTION'
    __bind_key__  = 'XORCISM'

    ROGGadgetID = Column(Integer, primary_key=True)
    InstructionID = Column(Integer, nullable=False)
    InstructionOrder = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<ROPGADGETINSTRUCTION {self.ROGGadgetID}>'

class ROPGADGETTAG(Base):
    __tablename__ = 'ROPGADGETTAG'
    __bind_key__  = 'XORCISM'

    ROPGadgetTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ROPGADGETTAG {self.ROPGadgetTagID}>'

class RSAPUBLICKEY(Base):
    __tablename__ = 'RSAPUBLICKEY'
    __bind_key__  = 'XORCISM'

    RSAPublicKeyID = Column(Integer, primary_key=True)
    RSAPublicKeyGUID = Column(Text)
    Modulus = Column(Text, nullable=False)
    Exponent = Column(Integer, nullable=False)
    isEncrypted = Column(Integer)
    CreationDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<RSAPUBLICKEY {self.RSAPublicKeyID}>'

class RSAPUBLICKEYACCESSRECORD(Base):
    __tablename__ = 'RSAPUBLICKEYACCESSRECORD'
    __bind_key__  = 'XORCISM'

    RSAPlublicKeyAccessRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<RSAPUBLICKEYACCESSRECORD {self.RSAPlublicKeyAccessRecordID}>'

class RULE(Base):
    __tablename__ = 'RULE'
    __bind_key__  = 'XORCISM'

    RuleID = Column(Integer, primary_key=True)
    RuleGUID = Column(Text)
    RuleTitle = Column(Text)
    RuleVersion = Column(Integer)
    RuleDescription = Column(Text)
    RuleContent = Column(Text)
    RuleVocabularyID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RULE {self.RuleID}>'

class RULECATEGORIES(Base):
    __tablename__ = 'RULECATEGORIES'
    __bind_key__  = 'XORCISM'

    RuleCategoriesID = Column(Integer, primary_key=True)
    RuleID = Column(Integer)
    RuleCategoryID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RULECATEGORIES {self.RuleCategoriesID}>'

class RULECATEGORY(Base):
    __tablename__ = 'RULECATEGORY'
    __bind_key__  = 'XORCISM'

    RuleCategoryID = Column(Integer, primary_key=True)
    CategoryID = Column(Integer)
    RuleCategoryName = Column(Text)
    RuleCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RULECATEGORY {self.RuleCategoryID}>'

class RULEPRODUCT(Base):
    __tablename__ = 'RULEPRODUCT'
    __bind_key__  = 'XORCISM'

    RuleProductID = Column(Integer, primary_key=True)
    RuleID = Column(Integer)
    RuleProductRelationship = Column(Text)
    ProductID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RULEPRODUCT {self.RuleProductID}>'

class RULEPROTOCOL(Base):
    __tablename__ = 'RULEPROTOCOL'
    __bind_key__  = 'XORCISM'

    RuleProtocolID = Column(Integer, primary_key=True)
    RuleID = Column(Integer)
    ProtocolID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RULEPROTOCOL {self.RuleProtocolID}>'

class RULEREFERENCE(Base):
    __tablename__ = 'RULEREFERENCE'
    __bind_key__  = 'XORCISM'

    RuleReferenceID = Column(Integer, primary_key=True)
    RuleID = Column(Integer)
    ReferenceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RULEREFERENCE {self.RuleReferenceID}>'

class SCENARIO(Base):
    __tablename__ = 'SCENARIO'
    __bind_key__  = 'XORCISM'

    ScenarioID = Column(Integer, primary_key=True)
    ScenarioName = Column(Text, nullable=False)
    ScenarioDescription = Column(Text)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SCENARIO {self.ScenarioID}>'

class SCENARIOFOROWASPTOP10(Base):
    __tablename__ = 'SCENARIOFOROWASPTOP10'
    __bind_key__  = 'XORCISM'

    OWASPTOP10ScenarioID = Column(Integer, primary_key=True)
    OWASPTOP10ID = Column(Integer, nullable=False)
    ScenarioID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<SCENARIOFOROWASPTOP10 {self.OWASPTOP10ScenarioID}>'

class SCHEDULE(Base):
    __tablename__ = 'SCHEDULE'
    __bind_key__  = 'XORCISM'

    ScheduleID = Column(Integer, primary_key=True)
    ScheduleGUID = Column(Text)

    def __repr__(self):
        return f'<SCHEDULE {self.ScheduleID}>'

class SCHEMA(Base):
    __tablename__ = 'SCHEMA'
    __bind_key__  = 'XORCISM'

    SchemaID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SCHEMA {self.SchemaID}>'

class SCORINGFORMULA(Base):
    __tablename__ = 'SCORINGFORMULA'
    __bind_key__  = 'XORCISM'

    ScoringFormulaID = Column(Integer, primary_key=True)
    ScoringFormulaName = Column(Text, nullable=False)
    ScoringFormulaAbbreviation = Column(Text)
    ScoringFormulaDescription = Column(Text)
    ScoringFormulaIndividualScore = Column(Text)
    ScoringFormulaHostScore = Column(Text)
    ScoringFormulaNotes = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SCORINGFORMULA {self.ScoringFormulaID}>'

class SCORINGSTATUS(Base):
    __tablename__ = 'SCORINGSTATUS'
    __bind_key__  = 'XORCISM'

    ScoringStatusID = Column(Integer, primary_key=True)
    ScoringStatusName = Column(Text)
    ScoringStatusValue = Column(Text)
    ScoringStatusDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SCORINGSTATUS {self.ScoringStatusID}>'

class SCORINGSYSTEM(Base):
    __tablename__ = 'SCORINGSYSTEM'
    __bind_key__  = 'XORCISM'

    ScoringSystemID = Column(Integer, primary_key=True)
    ScoringSystemName = Column(Text, nullable=False)
    ScoringSystemDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SCORINGSYSTEM {self.ScoringSystemID}>'

class SCORINGSYSTEMDESCRIPTION(Base):
    __tablename__ = 'SCORINGSYSTEMDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ScoringSystemDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SCORINGSYSTEMDESCRIPTION {self.ScoringSystemDescriptionID}>'

class SCORINGSYSTEMFORMULAS(Base):
    __tablename__ = 'SCORINGSYSTEMFORMULAS'
    __bind_key__  = 'XORCISM'

    ScoringSystemID = Column(Integer, primary_key=True)
    ScoringFormulaID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SCORINGSYSTEMFORMULAS {self.ScoringSystemID}>'

class SCORINGSYSTEMREFERENCE(Base):
    __tablename__ = 'SCORINGSYSTEMREFERENCE'
    __bind_key__  = 'XORCISM'

    ScoringSystemID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<SCORINGSYSTEMREFERENCE {self.ScoringSystemID}>'

class SCORINGSYSTEMTAG(Base):
    __tablename__ = 'SCORINGSYSTEMTAG'
    __bind_key__  = 'XORCISM'

    ScoringSystemTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SCORINGSYSTEMTAG {self.ScoringSystemTagID}>'

class SCRIPT(Base):
    __tablename__ = 'SCRIPT'
    __bind_key__  = 'XORCISM'

    ScriptID = Column(Integer, primary_key=True)
    CommandsID = Column(Integer, nullable=False)
    CommandID = Column(Integer, nullable=False)
    CommandArgumentValue = Column(Text)
    ScriptName = Column(Text)
    ScriptDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SCRIPT {self.ScriptID}>'

class SCRIPTDESCRIPTION(Base):
    __tablename__ = 'SCRIPTDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ScriptDescriptionID = Column(Integer, primary_key=True)
    ScriptID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SCRIPTDESCRIPTION {self.ScriptDescriptionID}>'

class SCRIPTTAG(Base):
    __tablename__ = 'SCRIPTTAG'
    __bind_key__  = 'XORCISM'

    ScriptTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SCRIPTTAG {self.ScriptTagID}>'

class SCRIPTVERSION(Base):
    __tablename__ = 'SCRIPTVERSION'
    __bind_key__  = 'XORCISM'

    ScriptVersionID = Column(Integer, primary_key=True)
    ScriptID = Column(Integer, nullable=False)
    VersionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SCRIPTVERSION {self.ScriptVersionID}>'

class SECONDARYOPERATIONPROPERTIES(Base):
    __tablename__ = 'SECONDARYOPERATIONPROPERTIES'
    __bind_key__  = 'XORCISM'

    SecondaryOperationPropertiesID = Column(Integer, primary_key=True)
    SecondaryOperationPropertiesName = Column(Text)
    SecondaryOperationPropertiesDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECONDARYOPERATIONPROPERTIES {self.SecondaryOperationPropertiesID}>'

class SECONDARYOPERATIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'SECONDARYOPERATIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    SecondaryOperationStrategicObjectiveID = Column(Integer, primary_key=True)
    SecondaryOperationStrategicObjectiveName = Column(Text)
    SecondaryOperationStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECONDARYOPERATIONSTRATEGICOBJECTIVE {self.SecondaryOperationStrategicObjectiveID}>'

class SECONDARYOPERATIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'SECONDARYOPERATIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    SecondaryOperationTacticalObjectiveID = Column(Integer, primary_key=True)
    SecondaryOperationTacticalObjectiveName = Column(Text)
    SecondaryOperationTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<SECONDARYOPERATIONTACTICALOBJECTIVE {self.SecondaryOperationTacticalObjectiveID}>'

class SECTION(Base):
    __tablename__ = 'SECTION'
    __bind_key__  = 'XORCISM'

    SectionID = Column(Integer, primary_key=True)
    SectionName = Column(Text)
    SectionDescription = Column(Text)
    SectionValue = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromdate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECTION {self.SectionID}>'

class SECTIONDESCRIPTION(Base):
    __tablename__ = 'SECTIONDESCRIPTION'
    __bind_key__  = 'XORCISM'

    SectionDescriptionID = Column(Integer, primary_key=True)
    SectionID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SECTIONDESCRIPTION {self.SectionDescriptionID}>'

class SECTIONREFERENCE(Base):
    __tablename__ = 'SECTIONREFERENCE'
    __bind_key__  = 'XORCISM'

    SectionReferenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECTIONREFERENCE {self.SectionReferenceID}>'

class SECTIONTAG(Base):
    __tablename__ = 'SECTIONTAG'
    __bind_key__  = 'XORCISM'

    SectionTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECTIONTAG {self.SectionTagID}>'

class SECURITYATTRIBUTE(Base):
    __tablename__ = 'SECURITYATTRIBUTE'
    __bind_key__  = 'XORCISM'

    SecurityAttributeID = Column(Integer, primary_key=True)
    SecurityAttributeCategoryID = Column(Integer, nullable=False)
    SecurityAttributeName = Column(Text, nullable=False)
    data_disclosure = Column(Text)
    SecurityAttributeStateID = Column(Integer)
    notes = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    durationvalue = Column(Integer)
    durationunit = Column(Text)
    IncidentID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SECURITYATTRIBUTE {self.SecurityAttributeID}>'

class SECURITYATTRIBUTECATEGORY(Base):
    __tablename__ = 'SECURITYATTRIBUTECATEGORY'
    __bind_key__  = 'XORCISM'

    SecurityAttributeCategoryID = Column(Integer, primary_key=True)
    SecurityAttributeCategoryName = Column(Text, nullable=False)
    SecurityAttributeCategoryDescription = Column(Text)

    def __repr__(self):
        return f'<SECURITYATTRIBUTECATEGORY {self.SecurityAttributeCategoryID}>'

class SECURITYATTRIBUTESTATE(Base):
    __tablename__ = 'SECURITYATTRIBUTESTATE'
    __bind_key__  = 'XORCISM'

    SecurityAttributeStateID = Column(Integer, primary_key=True)
    SecurityAttributeCategoryID = Column(Integer, nullable=False)
    SecurityAttributeStateName = Column(Text, nullable=False)
    SecurityAttributeStateDescription = Column(Text)

    def __repr__(self):
        return f'<SECURITYATTRIBUTESTATE {self.SecurityAttributeStateID}>'

class SECURITYATTRIBUTEVARIETY(Base):
    __tablename__ = 'SECURITYATTRIBUTEVARIETY'
    __bind_key__  = 'XORCISM'

    SecurityAttributeVarietyID = Column(Integer, primary_key=True)
    SecurityAttributeCategoryID = Column(Integer, nullable=False)
    SecurityAttributeVarietyName = Column(Text, nullable=False)
    SecurityAttributeVarietyDescription = Column(Text)

    def __repr__(self):
        return f'<SECURITYATTRIBUTEVARIETY {self.SecurityAttributeVarietyID}>'

class SECURITYCHANGE(Base):
    __tablename__ = 'SECURITYCHANGE'
    __bind_key__  = 'XORCISM'

    SecurityChangeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYCHANGE {self.SecurityChangeID}>'

class SECURITYCOMPROMISEENUM(Base):
    __tablename__ = 'SECURITYCOMPROMISEENUM'
    __bind_key__  = 'XORCISM'

    SecurityCompromiseEnumID = Column(Integer, primary_key=True)
    SecurityCompromiseEnumName = Column(Text)
    SecurityCompromiseEnumDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<SECURITYCOMPROMISEENUM {self.SecurityCompromiseEnumID}>'

class SECURITYCONTROL(Base):
    __tablename__ = 'SECURITYCONTROL'
    __bind_key__  = 'XORCISM'

    SecurityControlID = Column(Integer, primary_key=True)
    SecurityControlGUID = Column(Text)
    ControlID = Column(Integer)
    SecurityControlName = Column(Text, nullable=False)
    SecurityControlAbbrevation = Column(Text)
    SecurityControlDescription = Column(Text)
    BaselineImpact = Column(Text)
    StatementDescription = Column(Text)
    VocabularyID = Column(Integer)
    SecurityControlVocabularyID = Column(Text)
    SecurityControlFamilyID = Column(Integer)
    SecurityControlParentID = Column(Integer)
    SecurityControlTypeID = Column(Integer)
    RepositoryID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ReliabilityID = Column(Integer)

    def __repr__(self):
        return f'<SECURITYCONTROL {self.SecurityControlID}>'

class SECURITYCONTROLCHANGERECORD(Base):
    __tablename__ = 'SECURITYCONTROLCHANGERECORD'
    __bind_key__  = 'XORCISM'

    SecurityControlChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYCONTROLCHANGERECORD {self.SecurityControlChangeRecordID}>'

class SECURITYCONTROLDESCRIPTION(Base):
    __tablename__ = 'SECURITYCONTROLDESCRIPTION'
    __bind_key__  = 'XORCISM'

    SecurityControlDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYCONTROLDESCRIPTION {self.SecurityControlDescriptionID}>'

class SECURITYCONTROLENVIRONMENT(Base):
    __tablename__ = 'SECURITYCONTROLENVIRONMENT'
    __bind_key__  = 'XORCISM'

    SecurityControlEnvironmentID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYCONTROLENVIRONMENT {self.SecurityControlEnvironmentID}>'

class SECURITYCONTROLFAMILY(Base):
    __tablename__ = 'SECURITYCONTROLFAMILY'
    __bind_key__  = 'XORCISM'

    SecurityControlFamilyID = Column(Integer, primary_key=True)
    SecurityControlFamilyName = Column(Text, nullable=False)
    SecurityControlFamilyDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYCONTROLFAMILY {self.SecurityControlFamilyID}>'

class SECURITYCONTROLFAMILYTAG(Base):
    __tablename__ = 'SECURITYCONTROLFAMILYTAG'
    __bind_key__  = 'XORCISM'

    SecurityControlFamilyTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYCONTROLFAMILYTAG {self.SecurityControlFamilyTagID}>'

class SECURITYCONTROLFORHUMANRISK(Base):
    __tablename__ = 'SECURITYCONTROLFORHUMANRISK'
    __bind_key__  = 'XORCISM'

    HumanRiskSecurityControlID = Column(Integer, primary_key=True)
    HumanRiskID = Column(Integer, nullable=False)
    SecurityControlID = Column(Integer, nullable=False)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<SECURITYCONTROLFORHUMANRISK {self.HumanRiskSecurityControlID}>'

class SECURITYCONTROLMAPPING(Base):
    __tablename__ = 'SECURITYCONTROLMAPPING'
    __bind_key__  = 'XORCISM'

    SecurityControlMappingID = Column(Integer, primary_key=True)
    SecurityControlRefID = Column(Integer, nullable=False)
    SecurityControlRefGUID = Column(Text)
    SecurityControlRelationship = Column(Text)
    SecurityControlMappingDescription = Column(Text)
    SecurityControlSubjectID = Column(Integer, nullable=False)
    SecurityControlSubjectGUID = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<SECURITYCONTROLMAPPING {self.SecurityControlMappingID}>'

class SECURITYCONTROLPRIORITY(Base):
    __tablename__ = 'SECURITYCONTROLPRIORITY'
    __bind_key__  = 'XORCISM'

    SecurityControlPriorityID = Column(Integer, primary_key=True)
    SecurityControlID = Column(Integer)
    PriorityLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYCONTROLPRIORITY {self.SecurityControlPriorityID}>'

class SECURITYCONTROLREFERENCE(Base):
    __tablename__ = 'SECURITYCONTROLREFERENCE'
    __bind_key__  = 'XORCISM'

    SecurityControlReferenceID = Column(Integer, primary_key=True)
    SecurityControlID = Column(Integer)
    SecurityControlGUID = Column(Text)
    ReferenceID = Column(Integer)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYCONTROLREFERENCE {self.SecurityControlReferenceID}>'

class SECURITYCONTROLSTRENGTH(Base):
    __tablename__ = 'SECURITYCONTROLSTRENGTH'
    __bind_key__  = 'XORCISM'

    SecurityControlStrenghtID = Column(Integer, primary_key=True)
    SecurityControlID = Column(Integer, nullable=False)
    ControlStrengthID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYCONTROLSTRENGTH {self.SecurityControlStrenghtID}>'

class SECURITYCONTROLTAG(Base):
    __tablename__ = 'SECURITYCONTROLTAG'
    __bind_key__  = 'XORCISM'

    SecurityControlTagID = Column(Integer, primary_key=True)
    SecurityControlID = Column(Integer)
    SecurityControlGUID = Column(Text)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYCONTROLTAG {self.SecurityControlTagID}>'

class SECURITYCONTROLTEST(Base):
    __tablename__ = 'SECURITYCONTROLTEST'
    __bind_key__  = 'XORCISM'

    SecurityControlTestID = Column(Integer, primary_key=True)
    SecurityControlTestGUID = Column(Text)
    SecurityControlID = Column(Integer)
    SecurityControlGUID = Column(Text)
    TestID = Column(Integer)
    TestGUID = Column(Text)
    TestVocabularyID = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYCONTROLTEST {self.SecurityControlTestID}>'

class SECURITYCONTROLTOOL(Base):
    __tablename__ = 'SECURITYCONTROLTOOL'
    __bind_key__  = 'XORCISM'

    SecurityControlToolID = Column(Integer, primary_key=True)
    SecurityControlID = Column(Integer, nullable=False)
    SecuriyControlGUID = Column(Text)
    RelationshipName = Column(Text)
    ToolInformationID = Column(Integer, nullable=False)
    ToolInformationGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYCONTROLTOOL {self.SecurityControlToolID}>'

class SECURITYCONTROLTYPE(Base):
    __tablename__ = 'SECURITYCONTROLTYPE'
    __bind_key__  = 'XORCISM'

    SecurityControlTypeID = Column(Integer, primary_key=True)
    SecurityControlTypeName = Column(Text)
    SecurityControlTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYCONTROLTYPE {self.SecurityControlTypeID}>'

class SECURITYCONTROLTYPETAG(Base):
    __tablename__ = 'SECURITYCONTROLTYPETAG'
    __bind_key__  = 'XORCISM'

    SecurityControlTypeTagID = Column(Integer, primary_key=True)
    SecurityControlTypeID = Column(Integer)
    TagID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYCONTROLTYPETAG {self.SecurityControlTypeTagID}>'

class SECURITYDEGRADATIONPROPERTIES(Base):
    __tablename__ = 'SECURITYDEGRADATIONPROPERTIES'
    __bind_key__  = 'XORCISM'

    SecurityDegradationPropertiesID = Column(Integer, primary_key=True)
    SecurityDegradationPropertiesName = Column(Text)
    SecurityDegradationPropertiesDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYDEGRADATIONPROPERTIES {self.SecurityDegradationPropertiesID}>'

class SECURITYDEGRADATIONSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'SECURITYDEGRADATIONSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    SecurityDegradationStrategicObjectiveID = Column(Integer, primary_key=True)
    SecurityDegradationStrategicObjectiveName = Column(Text)
    SecurityDegradationStrategicObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYDEGRADATIONSTRATEGICOBJECTIVE {self.SecurityDegradationStrategicObjectiveID}>'

class SECURITYDEGRADATIONTACTICALOBJECTIVE(Base):
    __tablename__ = 'SECURITYDEGRADATIONTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    SecurityDegradationTacticalObjectiveID = Column(Integer, primary_key=True)
    SecurityDegradationTacticalObjectiveName = Column(Text)
    SecurityDegradationTacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<SECURITYDEGRADATIONTACTICALOBJECTIVE {self.SecurityDegradationTacticalObjectiveID}>'

class SECURITYDOMAIN(Base):
    __tablename__ = 'SECURITYDOMAIN'
    __bind_key__  = 'XORCISM'

    SecurityDomainID = Column(Integer, primary_key=True)
    SecurityDomainGUID = Column(Text)
    SecurityDomainName = Column(Text)
    SecurityDomainDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYDOMAIN {self.SecurityDomainID}>'

class SECURITYDOMAINMATURITY(Base):
    __tablename__ = 'SECURITYDOMAINMATURITY'
    __bind_key__  = 'XORCISM'

    SecurityDomainMaturityID = Column(Integer, primary_key=True)
    SecurityDomainID = Column(Integer)
    SecurityDomainGUID = Column(Text)
    MaturityLevelID = Column(Integer)
    MaturityLevelGUID = Column(Text)
    OrganisationID = Column(Integer)
    OrganizationalUnitID = Column(Integer)
    PersonID = Column(Integer)
    SecurityDomainMaturityDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    LastCheckedDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYDOMAINMATURITY {self.SecurityDomainMaturityID}>'

class SECURITYDOMAINOBJECTIVE(Base):
    __tablename__ = 'SECURITYDOMAINOBJECTIVE'
    __bind_key__  = 'XORCISM'

    SecurityDomainObjectiveID = Column(Integer, primary_key=True)
    SecurityDomainID = Column(Integer)
    SecurityDomainGUID = Column(Text)
    ObjectiveID = Column(Integer)
    ObjectiveGUID = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYDOMAINOBJECTIVE {self.SecurityDomainObjectiveID}>'

class SECURITYDOMAINPROCESS(Base):
    __tablename__ = 'SECURITYDOMAINPROCESS'
    __bind_key__  = 'XORCISM'

    SecurityDomainProcessID = Column(Integer, primary_key=True)
    SecurityDomainID = Column(Integer, nullable=False)
    SecurityDomainGUID = Column(Text)
    SecurityProcessID = Column(Integer, nullable=False)
    SecurityProcessGUID = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYDOMAINPROCESS {self.SecurityDomainProcessID}>'

class SECURITYDOMAINTAG(Base):
    __tablename__ = 'SECURITYDOMAINTAG'
    __bind_key__  = 'XORCISM'

    SecurityDomainTagID = Column(Integer, primary_key=True)
    SecurityDomainID = Column(Integer)
    SecurityDomainGUID = Column(Text)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYDOMAINTAG {self.SecurityDomainTagID}>'

class SECURITYEVALUATION(Base):
    __tablename__ = 'SECURITYEVALUATION'
    __bind_key__  = 'XORCISM'

    SecurityEvaluationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYEVALUATION {self.SecurityEvaluationID}>'

class SECURITYLABEL(Base):
    __tablename__ = 'SECURITYLABEL'
    __bind_key__  = 'XORCISM'

    SecurityLabelID = Column(Integer, primary_key=True)
    LabelID = Column(Integer)
    SecurityLabelName = Column(Text)
    SecurityLabelDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYLABEL {self.SecurityLabelID}>'

class SECURITYLABELREFERENCE(Base):
    __tablename__ = 'SECURITYLABELREFERENCE'
    __bind_key__  = 'XORCISM'

    SecurityLabelReferenceID = Column(Integer, primary_key=True)
    SecurityLabelID = Column(Integer, nullable=False)
    SecurityLabelGUID = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYLABELREFERENCE {self.SecurityLabelReferenceID}>'

class SECURITYMARKING(Base):
    __tablename__ = 'SECURITYMARKING'
    __bind_key__  = 'XORCISM'

    SecurityMarkingID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYMARKING {self.SecurityMarkingID}>'

class SECURITYMETRIC(Base):
    __tablename__ = 'SECURITYMETRIC'
    __bind_key__  = 'XORCISM'

    SecurityMetricID = Column(Integer, primary_key=True)
    SecurityMetricGUID = Column(Text)
    SecurityMetricName = Column(Text)
    SecurityMetricDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYMETRIC {self.SecurityMetricID}>'

class SECURITYMETRICDESCRIPTION(Base):
    __tablename__ = 'SECURITYMETRICDESCRIPTION'
    __bind_key__  = 'XORCISM'

    SecurityMetricDescriptionID = Column(Integer, primary_key=True)
    SecurityMetricID = Column(Integer)
    SecurityMetricGUID = Column(Text)
    DescriptionID = Column(Integer)
    DescriptionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYMETRICDESCRIPTION {self.SecurityMetricDescriptionID}>'

class SECURITYMETRICREFERENCE(Base):
    __tablename__ = 'SECURITYMETRICREFERENCE'
    __bind_key__  = 'XORCISM'

    SecurityMetricReferenceID = Column(Integer, primary_key=True)
    SecurityMetricID = Column(Integer)
    SecurityMetricGUID = Column(Text)
    ReferenceID = Column(Integer)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYMETRICREFERENCE {self.SecurityMetricReferenceID}>'

class SECURITYMETRICTAG(Base):
    __tablename__ = 'SECURITYMETRICTAG'
    __bind_key__  = 'XORCISM'

    SecurityMetricTagID = Column(Integer, primary_key=True)
    SecurityMetricID = Column(Integer)
    SecurityMetricGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYMETRICTAG {self.SecurityMetricTagID}>'

class SECURITYNOTIFICATION(Base):
    __tablename__ = 'SECURITYNOTIFICATION'
    __bind_key__  = 'XORCISM'

    SecurityNotificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYNOTIFICATION {self.SecurityNotificationID}>'

class SECURITYPRINCIPLE(Base):
    __tablename__ = 'SECURITYPRINCIPLE'
    __bind_key__  = 'XORCISM'

    SecurityPrincipleID = Column(Integer, primary_key=True)
    SecurityPrincipleGUID = Column(Text)
    SecurityPrincipleName = Column(Text, nullable=False)
    SecurityPrincipleDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYPRINCIPLE {self.SecurityPrincipleID}>'

class SECURITYPRINCIPLEDESCRIPTION(Base):
    __tablename__ = 'SECURITYPRINCIPLEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    SecurityPrincipleDescriptionID = Column(Integer, primary_key=True)
    SecurityPrincipleID = Column(Integer)
    SecurityPrincipleGUID = Column(Text)
    DescriptionID = Column(Integer)
    DescriptionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYPRINCIPLEDESCRIPTION {self.SecurityPrincipleDescriptionID}>'

class SECURITYPRINCIPLEFORATTACKPATTERN(Base):
    __tablename__ = 'SECURITYPRINCIPLEFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternSecurityPrincipleID = Column(Integer, primary_key=True)
    SecurityPrincipleID = Column(Integer, nullable=False)
    SecurityPrincipleGUID = Column(Text)
    AttackPatternID = Column(Integer, nullable=False)
    AttackPatternGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYPRINCIPLEFORATTACKPATTERN {self.AttackPatternSecurityPrincipleID}>'

class SECURITYPRINCIPLEREFERENCE(Base):
    __tablename__ = 'SECURITYPRINCIPLEREFERENCE'
    __bind_key__  = 'XORCISM'

    SecurityPrincipleReferenceID = Column(Integer, primary_key=True)
    SecurityPrincipleID = Column(Integer)
    SecurityPrincipleGUID = Column(Text)
    ReferenceID = Column(Integer)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYPRINCIPLEREFERENCE {self.SecurityPrincipleReferenceID}>'

class SECURITYPRINCIPLETAG(Base):
    __tablename__ = 'SECURITYPRINCIPLETAG'
    __bind_key__  = 'XORCISM'

    SecurityPrincipleTagID = Column(Integer, primary_key=True)
    SecurityPrincipleTagGUID = Column(Text)
    SecurityPrincipleID = Column(Integer)
    SecurityPrincipleGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYPRINCIPLETAG {self.SecurityPrincipleTagID}>'

class SECURITYPROCESS(Base):
    __tablename__ = 'SECURITYPROCESS'
    __bind_key__  = 'XORCISM'

    SecurityProcessID = Column(Integer, primary_key=True)
    SecurityProcessGUID = Column(Text)
    SecurityProcessName = Column(Text)
    SecurityProcessDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYPROCESS {self.SecurityProcessID}>'

class SECURITYPROCESSMATURITYLEVEL(Base):
    __tablename__ = 'SECURITYPROCESSMATURITYLEVEL'
    __bind_key__  = 'XORCISM'

    SecurityProcessMaturityLevelID = Column(Integer, primary_key=True)
    SecurityProcessMaturityLevelGUID = Column(Text)
    SecurityProcessID = Column(Integer)
    SecurityProcessGUID = Column(Text)
    MaturityLevelID = Column(Integer)
    MaturityLevelGUID = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYPROCESSMATURITYLEVEL {self.SecurityProcessMaturityLevelID}>'

class SECURITYPROGRAM(Base):
    __tablename__ = 'SECURITYPROGRAM'
    __bind_key__  = 'XORCISM'

    SecurityProgramID = Column(Integer, primary_key=True)
    SecurityProgramGUID = Column(Text)
    SecurityProgramName = Column(Text, nullable=False)
    SecurityProgramDescription = Column(Text)
    VocabularyID = Column(Integer)
    SecurityProgramTypeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYPROGRAM {self.SecurityProgramID}>'

class SECURITYPROGRAMPROJECT(Base):
    __tablename__ = 'SECURITYPROGRAMPROJECT'
    __bind_key__  = 'XORCISM'

    SecurityProgramProjectID = Column(Integer, primary_key=True)
    SecurityProgramID = Column(Integer)
    SecurityProgramGUID = Column(Text)
    ProjectID = Column(Integer)
    ProjectGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYPROGRAMPROJECT {self.SecurityProgramProjectID}>'

class SECURITYPROGRAMTYPE(Base):
    __tablename__ = 'SECURITYPROGRAMTYPE'
    __bind_key__  = 'XORCISM'

    SecurityProgramTypeID = Column(Integer, primary_key=True)
    SecurityProgramTypeName = Column(Text, nullable=False)
    SecurityProgramTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYPROGRAMTYPE {self.SecurityProgramTypeID}>'

class SECURITYREQUIREMENT(Base):
    __tablename__ = 'SECURITYREQUIREMENT'
    __bind_key__  = 'XORCISM'

    SecurityRequirementID = Column(Integer, primary_key=True)
    RequirementID = Column(Integer)
    RequirementGUID = Column(Text)
    SecurityRequirementGUID = Column(Text)
    SecurityRequirementTitle = Column(Text)
    SecurityRequirementDescription = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYREQUIREMENT {self.SecurityRequirementID}>'

class SECURITYREQUIREMENTCONTROL(Base):
    __tablename__ = 'SECURITYREQUIREMENTCONTROL'
    __bind_key__  = 'XORCISM'

    SecurityRequirementControlID = Column(Integer, primary_key=True)
    SecurityRequirementID = Column(Integer)
    SecurityRequirementGUID = Column(Text)
    SecurityControlID = Column(Integer)
    SecurityControlGUID = Column(Text)
    EffectivenessID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYREQUIREMENTCONTROL {self.SecurityRequirementControlID}>'

class SECURITYREQUIREMENTFORATTACKPATTERN(Base):
    __tablename__ = 'SECURITYREQUIREMENTFORATTACKPATTERN'
    __bind_key__  = 'XORCISM'

    AttackPatternSecurityRequirementID = Column(Integer, primary_key=True)
    SecurityRequirementID = Column(Integer, nullable=False)
    SecurityRequirementGUID = Column(Text)
    AttackPatternID = Column(Integer, nullable=False)
    AttackPatternGUID = Column(Text)
    capec_id = Column(Text)
    AttackPatternSecurityRequirementDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SECURITYREQUIREMENTFORATTACKPATTERN {self.AttackPatternSecurityRequirementID}>'

class SECURITYREQUIREMENTMAPPING(Base):
    __tablename__ = 'SECURITYREQUIREMENTMAPPING'
    __bind_key__  = 'XORCISM'

    SecurityRequirementMappingID = Column(Integer, primary_key=True)
    AssuranceRequirementID = Column(Integer)
    AssuranceRequirementGUID = Column(Text)
    SecurityRequirementRefID = Column(Integer, nullable=False)
    SecurityRequirementRefGUID = Column(Text)
    SecurityRequirementRelationship = Column(Text)
    SecurityRequirementDescription = Column(Text)
    SecurityRequirementSubjectID = Column(Integer)
    SecurityRequirementSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYREQUIREMENTMAPPING {self.SecurityRequirementMappingID}>'

class SECURITYREQUIREMENTTAG(Base):
    __tablename__ = 'SECURITYREQUIREMENTTAG'
    __bind_key__  = 'XORCISM'

    SecurityRequirementTagID = Column(Integer, primary_key=True)
    SecurityRequirementID = Column(Integer)
    SecurityRequirementGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYREQUIREMENTTAG {self.SecurityRequirementTagID}>'

class SECURITYREQUIREMENTTEST(Base):
    __tablename__ = 'SECURITYREQUIREMENTTEST'
    __bind_key__  = 'XORCISM'

    SecurityRequirementTestID = Column(Integer, primary_key=True)
    SecurityRequirementTestGUID = Column(Text)
    SecurityRequirementID = Column(Integer)
    SecurityRequirementGUID = Column(Text)
    TestID = Column(Integer)
    TestGUID = Column(Text)
    TestVocabularyID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SECURITYREQUIREMENTTEST {self.SecurityRequirementTestID}>'

class SECURITYRISKANALYSIS(Base):
    __tablename__ = 'SECURITYRISKANALYSIS'
    __bind_key__  = 'XORCISM'

    SecurityRiskAnalysisID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SECURITYRISKANALYSIS {self.SecurityRiskAnalysisID}>'

class SEMAPHORE(Base):
    __tablename__ = 'SEMAPHORE'
    __bind_key__  = 'XORCISM'

    SemaphoreID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SEMAPHORE {self.SemaphoreID}>'

class SENSOR(Base):
    __tablename__ = 'SENSOR'
    __bind_key__  = 'XORCISM'

    SensorID = Column(Integer, primary_key=True)
    SensorGUID = Column(Text)
    SensorName = Column(Text)
    SensorDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    SensorVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SENSOR {self.SensorID}>'

class SENSORTOOL(Base):
    __tablename__ = 'SENSORTOOL'
    __bind_key__  = 'XORCISM'

    SensorToolID = Column(Integer, primary_key=True)
    SensorID = Column(Integer, nullable=False)
    ToolID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    SensorToolDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<SENSORTOOL {self.SensorToolID}>'

class SERVICEACTIONNAME(Base):
    __tablename__ = 'SERVICEACTIONNAME'
    __bind_key__  = 'XORCISM'

    ServiceActionNameID = Column(Integer, primary_key=True)
    ServiceActionNameName = Column(Text, nullable=False)
    ServiceActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SERVICEACTIONNAME {self.ServiceActionNameID}>'

class SERVICECATEGORY(Base):
    __tablename__ = 'SERVICECATEGORY'
    __bind_key__  = 'XORCISM'

    ServiceCategoryID = Column(Integer, primary_key=True)
    ServiceCategoryName = Column(Text, nullable=False)
    ServiceCategoryDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    StatusID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SERVICECATEGORY {self.ServiceCategoryID}>'

class SESSION(Base):
    __tablename__ = 'SESSION'
    __bind_key__  = 'XORCISM'

    SessionID = Column(Integer, primary_key=True)
    UserID = Column(Text)
    SessionIDValue = Column(Text)
    SessionName = Column(Text)
    SessionDescription = Column(Text)
    DateStart = Column(Text)
    DateEnd = Column(Text)
    StatusID = Column(Integer)
    Status = Column(Text)
    ServiceCategoryID = Column(Integer)
    Parameters = Column(LargeBinary)
    SessionCronID = Column(Integer)
    information = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SESSION {self.SessionID}>'

class SESSIONCOOKIE(Base):
    __tablename__ = 'SESSIONCOOKIE'
    __bind_key__  = 'XORCISM'

    SessionCookieID = Column(Integer, primary_key=True)
    SessionID = Column(Integer, nullable=False)
    SessionGUID = Column(Text)
    CookieID = Column(Integer, nullable=False)
    CookieGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    SessionCookieName = Column(Text)
    SessionCookieDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SESSIONCOOKIE {self.SessionCookieID}>'

class SESSIONCOOKIEATTRIBUTEVALUE(Base):
    __tablename__ = 'SESSIONCOOKIEATTRIBUTEVALUE'
    __bind_key__  = 'XORCISM'

    SessionCookieAttributeValueID = Column(Integer, primary_key=True)
    SessionCookieID = Column(Integer, nullable=False)
    SessionCookieGUID = Column(Text)
    AttributeValueID = Column(Integer, nullable=False)
    AttributeValueGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    SessionCookieAttributeValueName = Column(Text)
    SessionCookieAttributeValueDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SESSIONCOOKIEATTRIBUTEVALUE {self.SessionCookieAttributeValueID}>'

class SESSIONCRON(Base):
    __tablename__ = 'SESSIONCRON'
    __bind_key__  = 'XORCISM'

    SessionCronID = Column(Integer, primary_key=True)
    UserID = Column(Text)
    CronExpression = Column(Text)
    Parameters = Column(LargeBinary)
    StatusID = Column(Integer)
    Status = Column(Text)
    ServiceCategoryID = Column(Integer)
    DateStart = Column(Text)
    DateEnd = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SESSIONCRON {self.SessionCronID}>'

class SETOPERATOR(Base):
    __tablename__ = 'SETOPERATOR'
    __bind_key__  = 'XORCISM'

    SetOperatorID = Column(Integer, primary_key=True)
    SetOperatorValue = Column(Text, nullable=False)
    SetOperatorDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SETOPERATOR {self.SetOperatorID}>'

class SEVERITYLEVEL(Base):
    __tablename__ = 'SEVERITYLEVEL'
    __bind_key__  = 'XORCISM'

    SeverityLevelID = Column(Integer, primary_key=True)
    SeverityLevelGUID = Column(Text)
    SeverityLevelName = Column(Text, nullable=False)
    SeverityLevelDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SEVERITYLEVEL {self.SeverityLevelID}>'

class SHELLCODE(Base):
    __tablename__ = 'SHELLCODE'
    __bind_key__  = 'XORCISM'

    ShellCodeID = Column(Integer, primary_key=True)
    CodeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ShellCodeName = Column(Text)
    ShellCodeDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<SHELLCODE {self.ShellCodeID}>'

class SIDTYPE(Base):
    __tablename__ = 'SIDTYPE'
    __bind_key__  = 'XORCISM'

    SIDTypeID = Column(Integer, primary_key=True)
    SIDTypeName = Column(Text, nullable=False)
    SIDTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SIDTYPE {self.SIDTypeID}>'

class SIGNAL(Base):
    __tablename__ = 'SIGNAL'
    __bind_key__  = 'XORCISM'

    SignalID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SIGNAL {self.SignalID}>'

class SIGNATURE(Base):
    __tablename__ = 'SIGNATURE'
    __bind_key__  = 'XORCISM'

    SignatureID = Column(Integer, primary_key=True)
    SignatureName = Column(Text, nullable=False)
    SignatureDescription = Column(Text)
    SignatureBase64Binary = Column(Text)
    SeverityLevelID = Column(Integer)
    SignatureSeverityLevel = Column(Text)
    VocabularyID = Column(Integer)
    SignatureTypeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SIGNATURE {self.SignatureID}>'

class SIGNATURECPE(Base):
    __tablename__ = 'SIGNATURECPE'
    __bind_key__  = 'XORCISM'

    CPESignatureID = Column(Integer, primary_key=True)
    SignatureID = Column(Integer, nullable=False)
    CPEID = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    SignatureCPEName = Column(Text)
    SignatureCPEDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SIGNATURECPE {self.CPESignatureID}>'

class SIGNATUREEXPLOIT(Base):
    __tablename__ = 'SIGNATUREEXPLOIT'
    __bind_key__  = 'XORCISM'

    ExploitSignatureID = Column(Integer, primary_key=True)
    SignatureID = Column(Integer, nullable=False)
    ExploitID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    SignatureExploitName = Column(Text)
    SignatureExploitDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    TrustLevelID = Column(Integer)

    def __repr__(self):
        return f'<SIGNATUREEXPLOIT {self.ExploitSignatureID}>'

class SIGNATUREMALWAREINSTANCE(Base):
    __tablename__ = 'SIGNATUREMALWAREINSTANCE'
    __bind_key__  = 'XORCISM'

    MalwareInstanceSignatureID = Column(Integer, primary_key=True)
    SignatureID = Column(Integer, nullable=False)
    MalwareInstanceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    SignatureMalwareInstanceName = Column(Text)
    SignatureMalwareInstanceDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<SIGNATUREMALWAREINSTANCE {self.MalwareInstanceSignatureID}>'

class SIGNATUREPORT(Base):
    __tablename__ = 'SIGNATUREPORT'
    __bind_key__  = 'XORCISM'

    SignatureID = Column(Integer, primary_key=True)
    PortID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SIGNATUREPORT {self.SignatureID}>'

class SIGNATUREPROTOCOL(Base):
    __tablename__ = 'SIGNATUREPROTOCOL'
    __bind_key__  = 'XORCISM'

    SignatureID = Column(Integer, primary_key=True)
    ProtocolID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SIGNATUREPROTOCOL {self.SignatureID}>'

class SIGNATUREREFERENCE(Base):
    __tablename__ = 'SIGNATUREREFERENCE'
    __bind_key__  = 'XORCISM'

    SignatureReferenceID = Column(Integer, primary_key=True)
    SignatureID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SIGNATUREREFERENCE {self.SignatureReferenceID}>'

class SIGNATURETYPE(Base):
    __tablename__ = 'SIGNATURETYPE'
    __bind_key__  = 'XORCISM'

    SignatureTypeID = Column(Integer, primary_key=True)
    SignatureTypeName = Column(Text, nullable=False)
    SignatureTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SIGNATURETYPE {self.SignatureTypeID}>'

class SIGNATURETYPEREFERENCE(Base):
    __tablename__ = 'SIGNATURETYPEREFERENCE'
    __bind_key__  = 'XORCISM'

    SitgnatureTypeReferenceID = Column(Integer, primary_key=True)
    SignatureTypeID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SIGNATURETYPEREFERENCE {self.SitgnatureTypeReferenceID}>'

class SIMPLEDATATYPE(Base):
    __tablename__ = 'SIMPLEDATATYPE'
    __bind_key__  = 'XORCISM'

    SimpleDataTypeID = Column(Integer, primary_key=True)
    DataTypeName = Column(Text, nullable=False)
    DataTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SIMPLEDATATYPE {self.SimpleDataTypeID}>'

class SKILL(Base):
    __tablename__ = 'SKILL'
    __bind_key__  = 'XORCISM'

    SkillID = Column(Integer, primary_key=True)
    SkillGUID = Column(Text)
    SkillName = Column(Text)
    SkillDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SKILL {self.SkillID}>'

class SKILLCATEGORY(Base):
    __tablename__ = 'SKILLCATEGORY'
    __bind_key__  = 'XORCISM'

    SkillCategoryID = Column(Integer, primary_key=True)
    SkillCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    SkillCategoryName = Column(Text)
    SkillCategoryDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SKILLCATEGORY {self.SkillCategoryID}>'

class SKILLCATEGORYTAG(Base):
    __tablename__ = 'SKILLCATEGORYTAG'
    __bind_key__  = 'XORCISM'

    SkillCategoryTagID = Column(Integer, primary_key=True)
    SkillCategoryID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SKILLCATEGORYTAG {self.SkillCategoryTagID}>'

class SKILLLEVEL(Base):
    __tablename__ = 'SKILLLEVEL'
    __bind_key__  = 'XORCISM'

    SkillLevelID = Column(Integer, primary_key=True)
    SkillLevelValue = Column(Text)
    SkillLevelDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SKILLLEVEL {self.SkillLevelID}>'

class SKILLTAG(Base):
    __tablename__ = 'SKILLTAG'
    __bind_key__  = 'XORCISM'

    SkillTagID = Column(Integer, primary_key=True)
    SkillID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SKILLTAG {self.SkillTagID}>'

class SMSMESSAGE(Base):
    __tablename__ = 'SMSMESSAGE'
    __bind_key__  = 'XORCISM'

    SMSMessageID = Column(Integer, primary_key=True)
    MessageID = Column(Integer)

    def __repr__(self):
        return f'<SMSMESSAGE {self.SMSMessageID}>'

class SOCKETACTIONNAME(Base):
    __tablename__ = 'SOCKETACTIONNAME'
    __bind_key__  = 'XORCISM'

    SocketActionNameID = Column(Integer, primary_key=True)
    SocketActionNameName = Column(Text, nullable=False)
    SocketActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<SOCKETACTIONNAME {self.SocketActionNameID}>'

class SOCKETADDRESS(Base):
    __tablename__ = 'SOCKETADDRESS'
    __bind_key__  = 'XORCISM'

    SocketAddressID = Column(Integer, primary_key=True)
    AddressID = Column(Integer)
    HostNameID = Column(Integer)
    PortID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SOCKETADDRESS {self.SocketAddressID}>'

class SOFTWARE(Base):
    __tablename__ = 'SOFTWARE'
    __bind_key__  = 'XORCISM'

    SoftwareID = Column(Integer, primary_key=True)
    SoftwareGUID = Column(Text)
    ProductID = Column(Integer)
    ProductGUID = Column(Text)
    ApplicationID = Column(Integer)
    ApplicationGUID = Column(Text)
    CPEID = Column(Integer)
    SWIDTAG = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SOFTWARE {self.SoftwareID}>'

class SOFTWARECHARACTERISTIC(Base):
    __tablename__ = 'SOFTWARECHARACTERISTIC'
    __bind_key__  = 'XORCISM'

    SoftwareCharacteristicID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SOFTWARECHARACTERISTIC {self.SoftwareCharacteristicID}>'

class SOFTWAREFILELIST(Base):
    __tablename__ = 'SOFTWAREFILELIST'
    __bind_key__  = 'XORCISM'

    SoftwareFileListID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SOFTWAREFILELIST {self.SoftwareFileListID}>'

class SOFTWARELICENSE(Base):
    __tablename__ = 'SOFTWARELICENSE'
    __bind_key__  = 'XORCISM'

    SoftwareLicenseID = Column(Integer, primary_key=True)
    SoftwareID = Column(Integer, nullable=False)
    SoftwareGUID = Column(Text)
    LicenseID = Column(Integer, nullable=False)
    LicenseGUID = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    CollectionMethodID = Column(Integer)
    LastCheckedDate = Column(Text)

    def __repr__(self):
        return f'<SOFTWARELICENSE {self.SoftwareLicenseID}>'

class SOURCE(Base):
    __tablename__ = 'SOURCE'
    __bind_key__  = 'XORCISM'

    SourceID = Column(Integer, primary_key=True)
    SourceGUID = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SOURCE {self.SourceID}>'

class SOURCECLASS(Base):
    __tablename__ = 'SOURCECLASS'
    __bind_key__  = 'XORCISM'

    SourceClassID = Column(Integer, primary_key=True)
    SourceClassName = Column(Text, nullable=False)
    SourceClassDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SOURCECLASS {self.SourceClassID}>'

class SOURCETYPE(Base):
    __tablename__ = 'SOURCETYPE'
    __bind_key__  = 'XORCISM'

    SourceTypeID = Column(Integer, primary_key=True)
    SourceTypeName = Column(Text, nullable=False)
    SourceTypeDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SOURCETYPE {self.SourceTypeID}>'

class SPLITFUNCTION(Base):
    __tablename__ = 'SPLITFUNCTION'
    __bind_key__  = 'XORCISM'

    SplitFunctionID = Column(Integer, primary_key=True)
    SplitDelimiter = Column(Text, nullable=False)
    OVALComponentGroupID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SPLITFUNCTION {self.SplitFunctionID}>'

class SPYINGSTRATEGICOBJECTIVE(Base):
    __tablename__ = 'SPYINGSTRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    SpyingStrategicObjectiveID = Column(Integer, primary_key=True)
    SpyingStrategicObjectiveName = Column(Text)
    SpyingStrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SPYINGSTRATEGICOBJECTIVE {self.SpyingStrategicObjectiveID}>'

class SPYINGTACTICALOBJECTIVE(Base):
    __tablename__ = 'SPYINGTACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    SpyingTacticalObjectiveID = Column(Integer, primary_key=True)
    SpyingTacticalObjectiveName = Column(Text)
    SpyingTacticalObjectiveDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SPYINGTACTICALOBJECTIVE {self.SpyingTacticalObjectiveID}>'

class SSDTENTRY(Base):
    __tablename__ = 'SSDTENTRY'
    __bind_key__  = 'XORCISM'

    SSDTEntryID = Column(Integer, primary_key=True)
    Service_Table_Base = Column(Text)
    Service_Counter_Table_Base = Column(Text)
    Number_Of_Services = Column(Integer)
    Argument_Table_Base = Column(Text)
    hooked = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<SSDTENTRY {self.SSDTEntryID}>'

class STAGE(Base):
    __tablename__ = 'STAGE'
    __bind_key__  = 'XORCISM'

    StageID = Column(Integer, primary_key=True)
    StageGUID = Column(Text)
    StageName = Column(Text)
    StageDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<STAGE {self.StageID}>'

class STAGECATEGORY(Base):
    __tablename__ = 'STAGECATEGORY'
    __bind_key__  = 'XORCISM'

    StageCategoryID = Column(Integer, primary_key=True)
    CategoryID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<STAGECATEGORY {self.StageCategoryID}>'

class STAGEDESCRIPTION(Base):
    __tablename__ = 'STAGEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    StageDescriptionID = Column(Integer, primary_key=True)
    StageID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)

    def __repr__(self):
        return f'<STAGEDESCRIPTION {self.StageDescriptionID}>'

class STANDARD(Base):
    __tablename__ = 'STANDARD'
    __bind_key__  = 'XORCISM'

    StandardID = Column(Integer, primary_key=True)
    StandardGUID = Column(Text)
    StandardVocabularyID = Column(Text)
    StandardName = Column(Text, nullable=False)
    StandardDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<STANDARD {self.StandardID}>'

class STANDARDCATEGORY(Base):
    __tablename__ = 'STANDARDCATEGORY'
    __bind_key__  = 'XORCISM'

    StandardCategoryID = Column(Integer, primary_key=True)
    CategoryID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<STANDARDCATEGORY {self.StandardCategoryID}>'

class STANDARDOBJECTIVE(Base):
    __tablename__ = 'STANDARDOBJECTIVE'
    __bind_key__  = 'XORCISM'

    StandardObjectiveID = Column(Integer, primary_key=True)
    StandardObjectiveVocabularyID = Column(Text)
    StandardID = Column(Integer)
    ObjectiveID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<STANDARDOBJECTIVE {self.StandardObjectiveID}>'

class STANDARDORGANISATION(Base):
    __tablename__ = 'STANDARDORGANISATION'
    __bind_key__  = 'XORCISM'

    StandardOrganisationID = Column(Integer, primary_key=True)
    StandardID = Column(Integer, nullable=False)
    RelationshipName = Column(Text)
    OrganisationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<STANDARDORGANISATION {self.StandardOrganisationID}>'

class STANDARDREFERENCE(Base):
    __tablename__ = 'STANDARDREFERENCE'
    __bind_key__  = 'XORCISM'

    StandardReferenceID = Column(Integer, primary_key=True)
    StandardID = Column(Integer, nullable=False)
    StandardGUID = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<STANDARDREFERENCE {self.StandardReferenceID}>'

class STANDARDRELATIONSHIP(Base):
    __tablename__ = 'STANDARDRELATIONSHIP'
    __bind_key__  = 'XORCISM'

    StandardRelationshipID = Column(Integer, primary_key=True)
    StandardRefID = Column(Integer, nullable=False)
    RelationshipName = Column(Text)
    StandardSubjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    ReferenceURL = Column(Text)

    def __repr__(self):
        return f'<STANDARDRELATIONSHIP {self.StandardRelationshipID}>'

class STANDARDSECTION(Base):
    __tablename__ = 'STANDARDSECTION'
    __bind_key__  = 'XORCISM'

    StandardSectionID = Column(Integer, primary_key=True)
    StandardID = Column(Integer)
    StandardGUID = Column(Text)
    SectionID = Column(Integer)
    SectionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<STANDARDSECTION {self.StandardSectionID}>'

class STANDARDSECTIONMAPPING(Base):
    __tablename__ = 'STANDARDSECTIONMAPPING'
    __bind_key__  = 'XORCISM'

    StandardSectionMappingID = Column(Integer, primary_key=True)
    StandardSectionRefID = Column(Integer)
    StandardSectionSubjectID = Column(Integer)
    ReferenceID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    MappingComment = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<STANDARDSECTIONMAPPING {self.StandardSectionMappingID}>'

class STANDARDSECURITYREQUIREMENT(Base):
    __tablename__ = 'STANDARDSECURITYREQUIREMENT'
    __bind_key__  = 'XORCISM'

    StandardSecurityRequirementID = Column(Integer, primary_key=True)
    StandardID = Column(Integer)
    SecurityRequirementID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<STANDARDSECURITYREQUIREMENT {self.StandardSecurityRequirementID}>'

class STANDARDTAG(Base):
    __tablename__ = 'STANDARDTAG'
    __bind_key__  = 'XORCISM'

    StandardTagID = Column(Integer, primary_key=True)
    StandardID = Column(Integer)
    TagID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<STANDARDTAG {self.StandardTagID}>'

class STANDARDVOCABULARY(Base):
    __tablename__ = 'STANDARDVOCABULARY'
    __bind_key__  = 'XORCISM'

    StandardVocabularyID = Column(Integer, primary_key=True)
    StandardID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<STANDARDVOCABULARY {self.StandardVocabularyID}>'

class STARTUPINFO(Base):
    __tablename__ = 'STARTUPINFO'
    __bind_key__  = 'XORCISM'

    StartupInfoID = Column(Integer, primary_key=True)
    lpDesktop = Column(Text)
    lpTitle = Column(Text)
    dwX = Column(Integer)
    dwY = Column(Integer)
    dwXSize = Column(Integer)
    dwYSize = Column(Integer)
    dwXCountChars = Column(Integer)
    dwYCountChars = Column(Integer)
    dwFillAttribute = Column(Integer)
    dwFlags = Column(Integer)
    wShowWindow = Column(Integer)

    def __repr__(self):
        return f'<STARTUPINFO {self.StartupInfoID}>'

class STATUS(Base):
    __tablename__ = 'STATUS'
    __bind_key__  = 'XORCISM'

    StatusID = Column(Integer, primary_key=True)
    StatusName = Column(Text, nullable=False)
    StatusDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<STATUS {self.StatusID}>'

class STRATEGICOBJECTIVE(Base):
    __tablename__ = 'STRATEGICOBJECTIVE'
    __bind_key__  = 'XORCISM'

    StrategicObjectiveID = Column(Integer, primary_key=True)
    StrategicObjectiveGUID = Column(Text)
    ObjectiveID = Column(Integer)
    StrategicObjectiveName = Column(Text)
    StrategicObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<STRATEGICOBJECTIVE {self.StrategicObjectiveID}>'

class STRATEGY(Base):
    __tablename__ = 'STRATEGY'
    __bind_key__  = 'XORCISM'

    StrategyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<STRATEGY {self.StrategyID}>'

class STRUCTUREDAUTHENTICATIONMECHANISM(Base):
    __tablename__ = 'STRUCTUREDAUTHENTICATIONMECHANISM'
    __bind_key__  = 'XORCISM'

    StructuredAuthenticationMechanismID = Column(Integer, primary_key=True)
    StructuredAuthenticationMechanismGUID = Column(Text)
    StructuredAuthenticationMechanismDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<STRUCTUREDAUTHENTICATIONMECHANISM {self.StructuredAuthenticationMechanismID}>'

class SUBCATEGORY(Base):
    __tablename__ = 'SUBCATEGORY'
    __bind_key__  = 'XORCISM'

    SubCategoryID = Column(Integer, primary_key=True)
    CategoryParentID = Column(Integer, nullable=False)
    CategoryID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CreationObjectID = Column(Integer)

    def __repr__(self):
        return f'<SUBCATEGORY {self.SubCategoryID}>'

class SUBJECTPUBLICKEY(Base):
    __tablename__ = 'SUBJECTPUBLICKEY'
    __bind_key__  = 'XORCISM'

    SubjectPublicKeyID = Column(Integer, primary_key=True)
    Public_Key_Algorithm = Column(Text, nullable=False)
    EncryptionID = Column(Integer)
    RSA_Public_Key = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SUBJECTPUBLICKEY {self.SubjectPublicKeyID}>'

class SUBSTRINGFUNCTION(Base):
    __tablename__ = 'SUBSTRINGFUNCTION'
    __bind_key__  = 'XORCISM'

    SubstringFunctionID = Column(Integer, primary_key=True)
    SubstringStart = Column(Integer, nullable=False)
    SubstringLength = Column(Integer, nullable=False)
    OVALComponentGroupID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SUBSTRINGFUNCTION {self.SubstringFunctionID}>'

class SUPPLYCHAIN(Base):
    __tablename__ = 'SUPPLYCHAIN'
    __bind_key__  = 'XORCISM'

    SupplyChainID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SUPPLYCHAIN {self.SupplyChainID}>'

class SUPPLYCHAINASSURANCE(Base):
    __tablename__ = 'SUPPLYCHAINASSURANCE'
    __bind_key__  = 'XORCISM'

    SupplyChainAssuranceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SUPPLYCHAINASSURANCE {self.SupplyChainAssuranceID}>'

class SUPPLYCHAINCOMPLIANCE(Base):
    __tablename__ = 'SUPPLYCHAINCOMPLIANCE'
    __bind_key__  = 'XORCISM'

    SupplyChainComplianceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SUPPLYCHAINCOMPLIANCE {self.SupplyChainComplianceID}>'

class SUPPRESSIONTYPE(Base):
    __tablename__ = 'SUPPRESSIONTYPE'
    __bind_key__  = 'XORCISM'

    SuppressionTypeID = Column(Integer, primary_key=True)
    SuppressionTypeName = Column(Text)
    SuppressionTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SUPPRESSIONTYPE {self.SuppressionTypeID}>'

class SUSPECTEDMALICIOUSREASON(Base):
    __tablename__ = 'SUSPECTEDMALICIOUSREASON'
    __bind_key__  = 'XORCISM'

    SuspectedMaliciousReasonID = Column(Integer, primary_key=True)
    SuspectedMaliciousReasonGUID = Column(Text)
    SuspectedMaliciousReasonName = Column(Text)
    ReasonID = Column(Integer)
    SuspectedMaliciousReasonDescription = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<SUSPECTEDMALICIOUSREASON {self.SuspectedMaliciousReasonID}>'

class SWENTAG(Base):
    __tablename__ = 'SWENTAG'
    __bind_key__  = 'XORCISM'

    SWENTAGID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SWENTAG {self.SWENTAGID}>'

class SWIDTAG(Base):
    __tablename__ = 'SWIDTAG'
    __bind_key__  = 'XORCISM'

    SWIDTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SWIDTAG {self.SWIDTagID}>'

class SWIDTAGCPE(Base):
    __tablename__ = 'SWIDTAGCPE'
    __bind_key__  = 'XORCISM'

    SWIDTagCPEID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<SWIDTAGCPE {self.SWIDTagCPEID}>'

class SYNCHRONIZATIONACTIONNAME(Base):
    __tablename__ = 'SYNCHRONIZATIONACTIONNAME'
    __bind_key__  = 'XORCISM'

    SynchronizationActionNameID = Column(Integer, primary_key=True)
    SynchronizationActionNameName = Column(Text, nullable=False)
    SynchronizationActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SYNCHRONIZATIONACTIONNAME {self.SynchronizationActionNameID}>'

class SYSTEM(Base):
    __tablename__ = 'SYSTEM'
    __bind_key__  = 'XORCISM'

    SystemID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)

    def __repr__(self):
        return f'<SYSTEM {self.SystemID}>'

class SYSTEMACTIONNAME(Base):
    __tablename__ = 'SYSTEMACTIONNAME'
    __bind_key__  = 'XORCISM'

    SystemActionNameID = Column(Integer, primary_key=True)
    SystemActionNameName = Column(Text, nullable=False)
    SystemActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    EnumerationVersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<SYSTEMACTIONNAME {self.SystemActionNameID}>'

class SYSTEMINFO(Base):
    __tablename__ = 'SYSTEMINFO'
    __bind_key__  = 'XORCISM'

    SystemInfoID = Column(Integer, primary_key=True)
    OSID = Column(Integer, nullable=False)
    architecture = Column(Text, nullable=False)
    primaryhostname = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<SYSTEMINFO {self.SystemInfoID}>'

class SYSTEMINFOFOROVALSYSTEMCHARACTERISTICS(Base):
    __tablename__ = 'SYSTEMINFOFOROVALSYSTEMCHARACTERISTICS'
    __bind_key__  = 'XORCISM'

    OVALSystemCharacteristicsID = Column(Integer, primary_key=True)
    SystemInfo = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SYSTEMINFOFOROVALSYSTEMCHARACTERISTICS {self.OVALSystemCharacteristicsID}>'

class SYSTEMTYPE(Base):
    __tablename__ = 'SYSTEMTYPE'
    __bind_key__  = 'XORCISM'

    SystemTypeID = Column(Integer, primary_key=True)
    SystemTypeGUID = Column(Text)
    SystemTypeName = Column(Text, nullable=False)
    SystemTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<SYSTEMTYPE {self.SystemTypeID}>'

class SYSTEMTYPEFORASSET(Base):
    __tablename__ = 'SYSTEMTYPEFORASSET'
    __bind_key__  = 'XORCISM'

    AssetSystemTypeID = Column(Integer, primary_key=True)
    AssetID = Column(Integer, nullable=False)
    SystemTypeID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<SYSTEMTYPEFORASSET {self.AssetSystemTypeID}>'

class SYSTEMTYPEFORTHREATACTORTTP(Base):
    __tablename__ = 'SYSTEMTYPEFORTHREATACTORTTP'
    __bind_key__  = 'XORCISM'

    SystemTypeID = Column(Integer, primary_key=True)
    ThreatActorTTPID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<SYSTEMTYPEFORTHREATACTORTTP {self.SystemTypeID}>'

class TACTIC(Base):
    __tablename__ = 'TACTIC'
    __bind_key__  = 'XORCISM'

    TacticID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TACTIC {self.TacticID}>'

class TACTICALOBJECTIVE(Base):
    __tablename__ = 'TACTICALOBJECTIVE'
    __bind_key__  = 'XORCISM'

    TacticalObjectiveID = Column(Integer, primary_key=True)
    TacticalObjectiveGUID = Column(Text)
    ObjectiveID = Column(Integer)
    TacticalObjectiveName = Column(Text)
    TacticalObjectiveDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TACTICALOBJECTIVE {self.TacticalObjectiveID}>'

class TACTICCATEGORY(Base):
    __tablename__ = 'TACTICCATEGORY'
    __bind_key__  = 'XORCISM'

    TacticCategoryID = Column(Integer, primary_key=True)
    CategoryID = Column(Integer)

    def __repr__(self):
        return f'<TACTICCATEGORY {self.TacticCategoryID}>'

class TAG(Base):
    __tablename__ = 'TAG'
    __bind_key__  = 'XORCISM'

    TagID = Column(Integer, primary_key=True)
    TagGUID = Column(Text)
    TagValue = Column(Text)
    casesensitive = Column(Integer)
    TagDescription = Column(Text)
    isEncrypted = Column(Integer)
    ImportanceID = Column(Integer)
    TagType = Column(Text)
    CollectionMethodID = Column(Integer)
    ToolID = Column(Integer)
    ToolGUID = Column(Text)
    SourceID = Column(Integer)
    SourceGUID = Column(Text)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    AccountID = Column(Integer)
    AccountGUID = Column(Text)
    UserID = Column(Integer)
    UserGUID = Column(Text)
    VocabularyID = Column(Integer)
    VocabularyGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<TAG {self.TagID}>'

class TAGBLACKLIST(Base):
    __tablename__ = 'TAGBLACKLIST'
    __bind_key__  = 'XORCISM'

    TagBlacklistID = Column(Integer, primary_key=True)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TAGBLACKLIST {self.TagBlacklistID}>'

class TAGCLASSIFICATION(Base):
    __tablename__ = 'TAGCLASSIFICATION'
    __bind_key__  = 'XORCISM'

    TagClassificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TAGCLASSIFICATION {self.TagClassificationID}>'

class TAGFORASSET(Base):
    __tablename__ = 'TAGFORASSET'
    __bind_key__  = 'XORCISM'

    TagAssetID = Column(Integer, primary_key=True)
    AssetID = Column(Integer)
    AssetGUID = Column(Text)
    TagID = Column(Integer)
    TagValue = Column(Text)
    TagAssetDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TAGFORASSET {self.TagAssetID}>'

class TAGRESTRICTION(Base):
    __tablename__ = 'TAGRESTRICTION'
    __bind_key__  = 'XORCISM'

    TagRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TAGRESTRICTION {self.TagRestrictionID}>'

class TAGTAG(Base):
    __tablename__ = 'TAGTAG'
    __bind_key__  = 'XORCISM'

    TagTagID = Column(Integer, primary_key=True)
    TagTagGUID = Column(Text)
    TagParentID = Column(Integer)
    TagParentGUID = Column(Text)
    TagSubjectID = Column(Integer)
    TagSubjectGUID = Column(Text)
    TagRelationship = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    SourceID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ImportanceID = Column(Integer)

    def __repr__(self):
        return f'<TAGTAG {self.TagTagID}>'

class TARGET(Base):
    __tablename__ = 'TARGET'
    __bind_key__  = 'XORCISM'

    TargetID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TARGET {self.TargetID}>'

class TARGETEDPLATFORMS(Base):
    __tablename__ = 'TARGETEDPLATFORMS'
    __bind_key__  = 'XORCISM'

    TargetedPlatformsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TARGETEDPLATFORMS {self.TargetedPlatformsID}>'

class TARGETEDPLATFORMSPECIFICATION(Base):
    __tablename__ = 'TARGETEDPLATFORMSPECIFICATION'
    __bind_key__  = 'XORCISM'

    TargetedPlatformsSpecification = Column(Integer, primary_key=True)
    TargetedPlatformsID = Column(Integer, nullable=False)
    PlatformSpecificationID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<TARGETEDPLATFORMSPECIFICATION {self.TargetedPlatformsID}>'

class TARGETS(Base):
    __tablename__ = 'TARGETS'
    __bind_key__  = 'XORCISM'

    TargetsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TARGETS {self.TargetsID}>'

class TASK(Base):
    __tablename__ = 'TASK'
    __bind_key__  = 'XORCISM'

    TaskID = Column(Integer, primary_key=True)
    TaskName = Column(Text)
    TaskDescription = Column(Text)
    TaskPriority = Column(Text)
    TaskStatus = Column(Text)
    CompletionPercentage = Column(Text)
    ExpectedCompletionDate = Column(Text)
    StartDate = Column(Text)
    DueDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TASK {self.TaskID}>'

class TASKACTION(Base):
    __tablename__ = 'TASKACTION'
    __bind_key__  = 'XORCISM'

    TaskActionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TASKACTION {self.TaskActionID}>'

class TASKACTIONLIST(Base):
    __tablename__ = 'TASKACTIONLIST'
    __bind_key__  = 'XORCISM'

    TaskActionListID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TASKACTIONLIST {self.TaskActionListID}>'

class TASKACTIONTYPE(Base):
    __tablename__ = 'TASKACTIONTYPE'
    __bind_key__  = 'XORCISM'

    TaskActionTypeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TASKACTIONTYPE {self.TaskActionTypeID}>'

class TASKATTACHMENT(Base):
    __tablename__ = 'TASKATTACHMENT'
    __bind_key__  = 'XORCISM'

    TaskAttachmentID = Column(Integer, primary_key=True)
    TaskID = Column(Integer)
    Title = Column(Text)
    Data = Column(LargeBinary)
    MimeType = Column(Text)

    def __repr__(self):
        return f'<TASKATTACHMENT {self.TaskAttachmentID}>'

class TASKDESCRIPTION(Base):
    __tablename__ = 'TASKDESCRIPTION'
    __bind_key__  = 'XORCISM'

    TaskDescriptionID = Column(Integer, primary_key=True)
    TaskID = Column(Integer, nullable=False)
    TaskGUID = Column(Text)
    DescriptionID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TASKDESCRIPTION {self.TaskDescriptionID}>'

class TASKFLAG(Base):
    __tablename__ = 'TASKFLAG'
    __bind_key__  = 'XORCISM'

    TaskFlagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TASKFLAG {self.TaskFlagID}>'

class TASKFORPROJECT(Base):
    __tablename__ = 'TASKFORPROJECT'
    __bind_key__  = 'XORCISM'

    ProjectTaskID = Column(Integer, primary_key=True)
    ProjectID = Column(Integer, nullable=False)
    TaskID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    ProjectTaskName = Column(Text)
    ProjectTaskDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TASKFORPROJECT {self.ProjectTaskID}>'

class TASKPERSON(Base):
    __tablename__ = 'TASKPERSON'
    __bind_key__  = 'XORCISM'

    TaskID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    RelationshipType = Column(Text)

    def __repr__(self):
        return f'<TASKPERSON {self.TaskID}>'

class TASKPRIORITY(Base):
    __tablename__ = 'TASKPRIORITY'
    __bind_key__  = 'XORCISM'

    TaskPriorityID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TASKPRIORITY {self.TaskPriorityID}>'

class TASKPRIORITYENUM(Base):
    __tablename__ = 'TASKPRIORITYENUM'
    __bind_key__  = 'XORCISM'

    TaskPriorityEnumID = Column(Integer, primary_key=True)
    TaskPriority = Column(Text)
    TaskPriorityDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TASKPRIORITYENUM {self.TaskPriorityEnumID}>'

class TASKSTATUS(Base):
    __tablename__ = 'TASKSTATUS'
    __bind_key__  = 'XORCISM'

    TaskStatusID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TASKSTATUS {self.TaskStatusID}>'

class TASKSTATUSENUM(Base):
    __tablename__ = 'TASKSTATUSENUM'
    __bind_key__  = 'XORCISM'

    TaskStatusEnumID = Column(Integer, primary_key=True)
    Status = Column(Text)
    TaskStatusDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TASKSTATUSENUM {self.TaskStatusEnumID}>'

class TASKTAG(Base):
    __tablename__ = 'TASKTAG'
    __bind_key__  = 'XORCISM'

    TaskTagID = Column(Integer, primary_key=True)
    TaskID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TASKTAG {self.TaskTagID}>'

class TASKTRIGGER(Base):
    __tablename__ = 'TASKTRIGGER'
    __bind_key__  = 'XORCISM'

    TaskTriggerID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TASKTRIGGER {self.TaskTriggerID}>'

class TASKTRIGGERFREQUENCY(Base):
    __tablename__ = 'TASKTRIGGERFREQUENCY'
    __bind_key__  = 'XORCISM'

    TaskTriggerFrequencyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TASKTRIGGERFREQUENCY {self.TaskTriggerFrequencyID}>'

class TAXONOMY(Base):
    __tablename__ = 'TAXONOMY'
    __bind_key__  = 'XORCISM'

    TaxonomyID = Column(Integer, primary_key=True)
    TaxonomyName = Column(Text, nullable=False)
    TaxonomyDescription = Column(Text)
    TaxonomyVersion = Column(Text)
    TaxonomyReference = Column(Text)
    CreatedDate = Column(Text)
    DateModified = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TAXONOMY {self.TaxonomyID}>'

class TAXONOMYNODE(Base):
    __tablename__ = 'TAXONOMYNODE'
    __bind_key__  = 'XORCISM'

    TaxonomyNodeID = Column(Integer, primary_key=True)
    TaxonomyID = Column(Integer)
    TaxonomyNodeName = Column(Text)
    TaxonomyMappedNodeID = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    TaxonomyNodeDescription = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TAXONOMYNODE {self.TaxonomyNodeID}>'

class TAXONOMYREFERENCE(Base):
    __tablename__ = 'TAXONOMYREFERENCE'
    __bind_key__  = 'XORCISM'

    TaxonomyReferenceID = Column(Integer, primary_key=True)
    TaxonomyID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    TaxonomyReferenceName = Column(Text)
    TaxonomyReferenceDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TAXONOMYREFERENCE {self.TaxonomyReferenceID}>'

class TCPSTATE(Base):
    __tablename__ = 'TCPSTATE'
    __bind_key__  = 'XORCISM'

    TCPStateID = Column(Integer, primary_key=True)
    TCPStateValue = Column(Text)
    TCPStateDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TCPSTATE {self.TCPStateID}>'

class TECHNICALCONTEXT(Base):
    __tablename__ = 'TECHNICALCONTEXT'
    __bind_key__  = 'XORCISM'

    TechnicalContextID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TECHNICALCONTEXT {self.TechnicalContextID}>'

class TECHNIQUE(Base):
    __tablename__ = 'TECHNIQUE'
    __bind_key__  = 'XORCISM'

    TechniqueID = Column(Integer, primary_key=True)
    TechniqueGUID = Column(Text)
    TechniqueName = Column(Text)
    TechniqueDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    ValidityID = Column(Integer)
    CreationObjectID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TECHNIQUE {self.TechniqueID}>'

class TECHNIQUECATEGORY(Base):
    __tablename__ = 'TECHNIQUECATEGORY'
    __bind_key__  = 'XORCISM'

    TechniqueCategoryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TECHNIQUECATEGORY {self.TechniqueCategoryID}>'

class TECHNIQUEDESCRIPTION(Base):
    __tablename__ = 'TECHNIQUEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    TechniqueDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TECHNIQUEDESCRIPTION {self.TechniqueDescriptionID}>'

class TECHNIQUEREFERENCE(Base):
    __tablename__ = 'TECHNIQUEREFERENCE'
    __bind_key__  = 'XORCISM'

    TechniqueReferenceID = Column(Integer, primary_key=True)
    TechniqueID = Column(Integer, nullable=False)
    TechniqueGUID = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    TechniqueReferenceDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    ConfidentialityLevelID = Column(Integer)

    def __repr__(self):
        return f'<TECHNIQUEREFERENCE {self.TechniqueReferenceID}>'

class TECHNIQUEREFERENCETAG(Base):
    __tablename__ = 'TECHNIQUEREFERENCETAG'
    __bind_key__  = 'XORCISM'

    TechniqueReferenceTagID = Column(Integer, primary_key=True)
    TechniqueReferenceID = Column(Integer)
    TechniqueReferenceGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    ImportanceID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    ConfidentialityLevelID = Column(Integer)

    def __repr__(self):
        return f'<TECHNIQUEREFERENCETAG {self.TechniqueReferenceTagID}>'

class TECHNIQUERESTRICTION(Base):
    __tablename__ = 'TECHNIQUERESTRICTION'
    __bind_key__  = 'XORCISM'

    TechniqueRestrictionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TECHNIQUERESTRICTION {self.TechniqueRestrictionID}>'

class TECHNIQUESTEP(Base):
    __tablename__ = 'TECHNIQUESTEP'
    __bind_key__  = 'XORCISM'

    TechniqueStepID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TECHNIQUESTEP {self.TechniqueStepID}>'

class TECHNIQUETAG(Base):
    __tablename__ = 'TECHNIQUETAG'
    __bind_key__  = 'XORCISM'

    TechniqueTagID = Column(Integer, primary_key=True)
    TechniqueID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TECHNIQUETAG {self.TechniqueTagID}>'

class TECHNOLOGY(Base):
    __tablename__ = 'TECHNOLOGY'
    __bind_key__  = 'XORCISM'

    TechnologyID = Column(Integer, primary_key=True)
    TechnologyGUID = Column(Text)
    TechnologyName = Column(Text)
    TechnologyDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TECHNOLOGY {self.TechnologyID}>'

class TECHNOLOGYDESCRIPTION(Base):
    __tablename__ = 'TECHNOLOGYDESCRIPTION'
    __bind_key__  = 'XORCISM'

    TechnologyDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TECHNOLOGYDESCRIPTION {self.TechnologyDescriptionID}>'

class TECHNOLOGYTAG(Base):
    __tablename__ = 'TECHNOLOGYTAG'
    __bind_key__  = 'XORCISM'

    TechnologyTagID = Column(Integer, primary_key=True)
    TechnologyID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TECHNOLOGYTAG {self.TechnologyTagID}>'

class TECHNOLOGYURI(Base):
    __tablename__ = 'TECHNOLOGYURI'
    __bind_key__  = 'XORCISM'

    TechnologyURIID = Column(Integer, primary_key=True)
    TechnologyID = Column(Integer, nullable=False)
    URIObjectID = Column(Integer, nullable=False)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TECHNOLOGYURI {self.TechnologyURIID}>'

class TELEPHONE(Base):
    __tablename__ = 'TELEPHONE'
    __bind_key__  = 'XORCISM'

    TelephoneID = Column(Integer, primary_key=True)
    TelephoneGUID = Column(Text)
    TelephoneNumber = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    LastCheckedDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TELEPHONE {self.TelephoneID}>'

class TELEPHONECALL(Base):
    __tablename__ = 'TELEPHONECALL'
    __bind_key__  = 'XORCISM'

    TelephoneCallID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TELEPHONECALL {self.TelephoneCallID}>'

class TELEPHONEFORORGANISATION(Base):
    __tablename__ = 'TELEPHONEFORORGANISATION'
    __bind_key__  = 'XORCISM'

    OrganisationTelephoneID = Column(Integer, primary_key=True)
    TelephoneID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TELEPHONEFORORGANISATION {self.OrganisationTelephoneID}>'

class TELEPHONEFORPERSON(Base):
    __tablename__ = 'TELEPHONEFORPERSON'
    __bind_key__  = 'XORCISM'

    PersonTelephoneID = Column(Integer, primary_key=True)
    TelephoneID = Column(Integer, nullable=False)
    PersonID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TELEPHONEFORPERSON {self.PersonTelephoneID}>'

class TELEPHONETAG(Base):
    __tablename__ = 'TELEPHONETAG'
    __bind_key__  = 'XORCISM'

    TelephoneTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TELEPHONETAG {self.TelephoneTagID}>'

class TEST(Base):
    __tablename__ = 'TEST'
    __bind_key__  = 'XORCISM'

    TestID = Column(Integer, primary_key=True)
    TestGUID = Column(Text)
    TestName = Column(Text)
    TestDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TEST {self.TestID}>'

class TESTMECHANISMEFFICACY(Base):
    __tablename__ = 'TESTMECHANISMEFFICACY'
    __bind_key__  = 'XORCISM'

    TestMechanismEfficacyID = Column(Integer, primary_key=True)
    Efficacy = Column(Text, nullable=False)
    EfficacyDescription = Column(Text)
    ConfidenceLevel = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TESTMECHANISMEFFICACY {self.TestMechanismEfficacyID}>'

class TESTMECHANISMID(Base):
    __tablename__ = 'TESTMECHANISMID'
    __bind_key__  = 'XORCISM'

    TestMechanismID = Column(Integer, primary_key=True)
    CyberObservableTestMechanismID = Column(Integer, nullable=False)
    TestMechanismIDREF = Column(Text, nullable=False)
    Information_Source = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TESTMECHANISMID {self.TestMechanismID}>'

class THEORETICALNOTE(Base):
    __tablename__ = 'THEORETICALNOTE'
    __bind_key__  = 'XORCISM'

    TheoreticalNoteID = Column(Integer, primary_key=True)
    TheoreticalNoteText = Column(Text)
    TheoreticalNoteTextClean = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THEORETICALNOTE {self.TheoreticalNoteID}>'

class THREADRUNNINGSTATUS(Base):
    __tablename__ = 'THREADRUNNINGSTATUS'
    __bind_key__  = 'XORCISM'

    ThreadRunningStatusID = Column(Integer, primary_key=True)
    Running_Status = Column(Text, nullable=False)
    ThreadRunningStatusDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREADRUNNINGSTATUS {self.ThreadRunningStatusID}>'

class TICKET(Base):
    __tablename__ = 'TICKET'
    __bind_key__  = 'XORCISM'

    TicketID = Column(Integer, primary_key=True)
    TicketGUID = Column(Text)
    StatusID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TICKET {self.TicketID}>'

class TICKETCHANGERECORD(Base):
    __tablename__ = 'TICKETCHANGERECORD'
    __bind_key__  = 'XORCISM'

    TicketChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TICKETCHANGERECORD {self.TicketChangeRecordID}>'

class TICKETCHANGEREQUEST(Base):
    __tablename__ = 'TICKETCHANGEREQUEST'
    __bind_key__  = 'XORCISM'

    TicketChangeRequestID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TICKETCHANGEREQUEST {self.TicketChangeRequestID}>'

class TICKETNOTIFICATION(Base):
    __tablename__ = 'TICKETNOTIFICATION'
    __bind_key__  = 'XORCISM'

    TicketNotificationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TICKETNOTIFICATION {self.TicketNotificationID}>'

class TICKETRACIMATRIX(Base):
    __tablename__ = 'TICKETRACIMATRIX'
    __bind_key__  = 'XORCISM'

    TicketRACIMatrixID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TICKETRACIMATRIX {self.TicketRACIMatrixID}>'

class TIMEDIFFERENCEFUNCTION(Base):
    __tablename__ = 'TIMEDIFFERENCEFUNCTION'
    __bind_key__  = 'XORCISM'

    TimeDifferenceFunctionID = Column(Integer, primary_key=True)
    DateTimeFormat1 = Column(Text, nullable=False)
    DateTimeFormat2 = Column(Text, nullable=False)

    def __repr__(self):
        return f'<TIMEDIFFERENCEFUNCTION {self.TimeDifferenceFunctionID}>'

class TIMELINE(Base):
    __tablename__ = 'TIMELINE'
    __bind_key__  = 'XORCISM'

    TimelineID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TIMELINE {self.TimelineID}>'

class TIMESHEET(Base):
    __tablename__ = 'TIMESHEET'
    __bind_key__  = 'XORCISM'

    TimesheetID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    TimesheetName = Column(Text)
    TimesheetDescription = Column(Text)
    TimeValue = Column(Text)
    TimeUnitID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ProjectID = Column(Integer)
    TaskID = Column(Integer)
    ProjectTaskID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TIMESHEET {self.TimesheetID}>'

class TIMESHEETPERSON(Base):
    __tablename__ = 'TIMESHEETPERSON'
    __bind_key__  = 'XORCISM'

    TimesheetPersonID = Column(Integer, primary_key=True)
    TimesheetID = Column(Integer, nullable=False)
    PersonID = Column(Integer, nullable=False)
    PersonRole = Column(Text)
    CreatedDate = Column(Text)
    TimesheetPersonDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    StatusID = Column(Integer)
    SignatureID = Column(Integer)

    def __repr__(self):
        return f'<TIMESHEETPERSON {self.TimesheetPersonID}>'

class TIMEUNIT(Base):
    __tablename__ = 'TIMEUNIT'
    __bind_key__  = 'XORCISM'

    TimeUnitID = Column(Integer, primary_key=True)
    TimeUnit = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    TimeUnitDescription = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TIMEUNIT {self.TimeUnitID}>'

class TIP(Base):
    __tablename__ = 'TIP'
    __bind_key__  = 'XORCISM'

    TipID = Column(Integer, primary_key=True)
    TipGUID = Column(Text)
    TipName = Column(Text)
    TipDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TIP {self.TipID}>'

class TIPCATEGORY(Base):
    __tablename__ = 'TIPCATEGORY'
    __bind_key__  = 'XORCISM'

    TipCategoryID = Column(Integer, primary_key=True)
    TipCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    TipCategoryName = Column(Text)
    TipCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TIPCATEGORY {self.TipCategoryID}>'

class TIPREFERENCE(Base):
    __tablename__ = 'TIPREFERENCE'
    __bind_key__  = 'XORCISM'

    TipReferenceID = Column(Integer, primary_key=True)
    TipID = Column(Integer, nullable=False)
    TipGUID = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    TipReferenceDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TIPREFERENCE {self.TipReferenceID}>'

class TITLE(Base):
    __tablename__ = 'TITLE'
    __bind_key__  = 'XORCISM'

    TitleID = Column(Integer, primary_key=True)
    TitleText = Column(Text)
    LocaleID = Column(Integer)
    VersionID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TITLE {self.TitleID}>'

class TOKEN(Base):
    __tablename__ = 'TOKEN'
    __bind_key__  = 'XORCISM'

    TokenID = Column(Integer, primary_key=True)
    TokenParentID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    TokenName = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TOKEN {self.TokenID}>'

class TOOL(Base):
    __tablename__ = 'TOOL'
    __bind_key__  = 'XORCISM'

    ToolID = Column(Integer, primary_key=True)
    ToolGUID = Column(Text)
    ToolName = Column(Text, nullable=False)
    ToolDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    ReliabilityID = Column(Integer)
    isEncrypted = Column(Integer)
    Category = Column(Text)
    ToolURL = Column(Text)

    def __repr__(self):
        return f'<TOOL {self.ToolID}>'

class TOOLACCESSRECORD(Base):
    __tablename__ = 'TOOLACCESSRECORD'
    __bind_key__  = 'XORCISM'

    ToolAccessRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TOOLACCESSRECORD {self.ToolAccessRecordID}>'

class TOOLCHANGERECORD(Base):
    __tablename__ = 'TOOLCHANGERECORD'
    __bind_key__  = 'XORCISM'

    ToolChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TOOLCHANGERECORD {self.ToolChangeRecordID}>'

class TOOLCODE(Base):
    __tablename__ = 'TOOLCODE'
    __bind_key__  = 'XORCISM'

    ToolCodeID = Column(Integer, primary_key=True)
    ToolCodeGUID = Column(Text)
    ToolID = Column(Integer)
    ToolGUID = Column(Text)
    CodeID = Column(Integer)
    CodeGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CreationObjectGUID = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethodID = Column(Integer)
    CollectionMethodGUID = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceLevelGUID = Column(Text)
    ConfidenceReasonID = Column(Integer)
    ConfidenceReasonGUID = Column(Text)
    SourceID = Column(Integer)
    SourceGUID = Column(Text)
    RepositoryID = Column(Integer)
    RepositoryGUID = Column(Text)

    def __repr__(self):
        return f'<TOOLCODE {self.ToolCodeID}>'

class TOOLFUNCTION(Base):
    __tablename__ = 'TOOLFUNCTION'
    __bind_key__  = 'XORCISM'

    ToolFunctionID = Column(Integer, primary_key=True)
    ToolFunctionGUID = Column(Text)
    ToolID = Column(Integer)
    ToolGUID = Column(Text)
    FunctionID = Column(Integer)
    FunctionGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TOOLFUNCTION {self.ToolFunctionID}>'

class TOOLINFORMATION(Base):
    __tablename__ = 'TOOLINFORMATION'
    __bind_key__  = 'XORCISM'

    ToolInformationID = Column(Integer, primary_key=True)
    ToolInformationGUID = Column(Text)
    ToolInformationIDREF = Column(Text)
    ToolName = Column(Text, nullable=False)
    ToolDescription = Column(Text)
    Vendor = Column(Text)
    Version = Column(Text)
    Service_Pack = Column(Text)
    Tool_Specific_Data = Column(Text)
    Tool_Hashes = Column(Text)
    Tool_Configuration = Column(Text)
    Execution_Environment = Column(Text)
    Errors = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TOOLINFORMATION {self.ToolInformationID}>'

class TOOLINFORMATIONDESCRIPTION(Base):
    __tablename__ = 'TOOLINFORMATIONDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ToolInformationDescriptionID = Column(Integer, primary_key=True)
    ToolInformationID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TOOLINFORMATIONDESCRIPTION {self.ToolInformationDescriptionID}>'

class TOOLINFORMATIONFORTOOL(Base):
    __tablename__ = 'TOOLINFORMATIONFORTOOL'
    __bind_key__  = 'XORCISM'

    ToolInformationForToolID = Column(Integer, primary_key=True)
    ToolID = Column(Integer, nullable=False)
    ToolInformationID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TOOLINFORMATIONFORTOOL {self.ToolInformationForToolID}>'

class TOOLINFORMATIONMETADATA(Base):
    __tablename__ = 'TOOLINFORMATIONMETADATA'
    __bind_key__  = 'XORCISM'

    ToolInformationID = Column(Integer, primary_key=True)
    MetadataID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<TOOLINFORMATIONMETADATA {self.ToolInformationID}>'

class TOOLINFORMATIONREFERENCE(Base):
    __tablename__ = 'TOOLINFORMATIONREFERENCE'
    __bind_key__  = 'XORCISM'

    ToolInformationReferenceID = Column(Integer, primary_key=True)
    ToolInformationID = Column(Integer, nullable=False)
    ToolInformationGUID = Column(Text)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    ToolReferenceTypeID = Column(Integer)
    ToolReferenceTypeGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    TrustLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TOOLINFORMATIONREFERENCE {self.ToolInformationReferenceID}>'

class TOOLLICENSE(Base):
    __tablename__ = 'TOOLLICENSE'
    __bind_key__  = 'XORCISM'

    ToolLicenseID = Column(Integer, primary_key=True)
    ToolID = Column(Integer, nullable=False)
    LicenseID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<TOOLLICENSE {self.ToolLicenseID}>'

class TOOLREFERENCE(Base):
    __tablename__ = 'TOOLREFERENCE'
    __bind_key__  = 'XORCISM'

    ToolReferenceID = Column(Integer, primary_key=True)
    ToolID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    ToolReferenceTypeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    ConfidentialityLevelID = Column(Integer)

    def __repr__(self):
        return f'<TOOLREFERENCE {self.ToolReferenceID}>'

class TOOLREFERENCETYPE(Base):
    __tablename__ = 'TOOLREFERENCETYPE'
    __bind_key__  = 'XORCISM'

    ToolReferenceTypeID = Column(Integer, primary_key=True)
    ToolReferenceTypeName = Column(Text, nullable=False)
    ToolReferenceTypeDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TOOLREFERENCETYPE {self.ToolReferenceTypeID}>'

class TOOLREPOSITORY(Base):
    __tablename__ = 'TOOLREPOSITORY'
    __bind_key__  = 'XORCISM'

    ToolRepositoryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TOOLREPOSITORY {self.ToolRepositoryID}>'

class TOOLTAG(Base):
    __tablename__ = 'TOOLTAG'
    __bind_key__  = 'XORCISM'

    ToolTagID = Column(Integer, primary_key=True)
    ToolTagGUID = Column(Text)
    ToolID = Column(Integer)
    ToolGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValdFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TOOLTAG {self.ToolTagID}>'

class TOOLTECHNOLOGY(Base):
    __tablename__ = 'TOOLTECHNOLOGY'
    __bind_key__  = 'XORCISM'

    ToolTechnologyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TOOLTECHNOLOGY {self.ToolTechnologyID}>'

class TOOLTYPE(Base):
    __tablename__ = 'TOOLTYPE'
    __bind_key__  = 'XORCISM'

    ToolTypeID = Column(Integer, primary_key=True)
    ToolTypeGUID = Column(Text)
    ToolTypeName = Column(Text, nullable=False)
    ToolTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text, nullable=False)
    isEncrypted = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<TOOLTYPE {self.ToolTypeID}>'

class TOOLTYPEFORTOOLINFORMATION(Base):
    __tablename__ = 'TOOLTYPEFORTOOLINFORMATION'
    __bind_key__  = 'XORCISM'

    ToolInformationID = Column(Integer, primary_key=True)
    ToolTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<TOOLTYPEFORTOOLINFORMATION {self.ToolInformationID}>'

class TOOLUSERAGENT(Base):
    __tablename__ = 'TOOLUSERAGENT'
    __bind_key__  = 'XORCISM'

    ToolUserAgentID = Column(Integer, primary_key=True)
    ToolID = Column(Integer)
    UserAgentID = Column(Integer)

    def __repr__(self):
        return f'<TOOLUSERAGENT {self.ToolUserAgentID}>'

class TRAINING(Base):
    __tablename__ = 'TRAINING'
    __bind_key__  = 'XORCISM'

    TrainingID = Column(Integer, primary_key=True)
    TrainingGUID = Column(Text)
    TrainingName = Column(Text)
    TrainingDescription = Column(Text)
    ValidFrom = Column(Text)   # date (ISO 8601, like the other dates)
    ValidUntil = Column(Text)  # date (ISO 8601)
    Status = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TRAINING {self.TrainingID}>'

class TRAININGFORPERSON(Base):
    __tablename__ = 'TRAININGFORPERSON'
    __bind_key__  = 'XORCISM'

    TrainingPersonID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    TrainingID = Column(Integer, nullable=False)
    DateEnrolled = Column(Text)   # date (ISO 8601, like the other dates)
    DateCompleted = Column(Text)  # date (ISO 8601)
    Status = Column(Text)
    ConfidenceLevel = Column(Integer)
    ValidFrom = Column(Text)   # date (ISO 8601)
    ValidUntil = Column(Text)  # date (ISO 8601)
    TenantID = Column(Integer)  # multi-tenant partitioning (TENANT_SCOPED_TABLES)

    def __repr__(self):
        return f'<TRAININGFORPERSON {self.TrainingPersonID}>'

class TRANSACTION(Base):
    __tablename__ = 'TRANSACTION'
    __bind_key__  = 'XORCISM'

    TrainingPersonID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    TrainingID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<TRANSACTION {self.TrainingPersonID}>'

class TRANSFORMATION(Base):
    __tablename__ = 'TRANSFORMATION'
    __bind_key__  = 'XORCISM'

    TransformationID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TRANSFORMATION {self.TransformationID}>'

class TREND(Base):
    __tablename__ = 'TREND'
    __bind_key__  = 'XORCISM'

    TrendID = Column(Integer, primary_key=True)
    TrendName = Column(Text, nullable=False)
    TrendDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TREND {self.TrendID}>'

class TRIGGERFREQUENCYENUM(Base):
    __tablename__ = 'TRIGGERFREQUENCYENUM'
    __bind_key__  = 'XORCISM'

    TriggerFrequencyEnumID = Column(Integer, primary_key=True)
    TriggerFrequency = Column(Text)
    TriggerFrequencyDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<TRIGGERFREQUENCYENUM {self.TriggerFrequencyEnumID}>'

class TRIGGERLIST(Base):
    __tablename__ = 'TRIGGERLIST'
    __bind_key__  = 'XORCISM'

    TriggerListID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TRIGGERLIST {self.TriggerListID}>'

class TRIGGERTYPEENUM(Base):
    __tablename__ = 'TRIGGERTYPEENUM'
    __bind_key__  = 'XORCISM'

    TriggerTypeEnumID = Column(Integer, primary_key=True)
    TriggerType = Column(Text)
    TriggerTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<TRIGGERTYPEENUM {self.TriggerTypeEnumID}>'

class TRUSTLEVEL(Base):
    __tablename__ = 'TRUSTLEVEL'
    __bind_key__  = 'XORCISM'

    TrustLevelID = Column(Integer, primary_key=True)
    TrustLevelGUID = Column(Text)
    TrustLevelName = Column(Text, nullable=False)
    TrustLevelDescription = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TRUSTLEVEL {self.TrustLevelID}>'

class TRUSTREASON(Base):
    __tablename__ = 'TRUSTREASON'
    __bind_key__  = 'XORCISM'

    TrustReasonID = Column(Integer, primary_key=True)
    TrustReasonGUID = Column(Text)
    ReasonID = Column(Integer)
    TrustReasonName = Column(Text)
    TrustReasonDescription = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<TRUSTREASON {self.TrustReasonID}>'

class TYPE(Base):
    __tablename__ = 'TYPE'
    __bind_key__  = 'XORCISM'

    TypeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<TYPE {self.TypeID}>'

class UNIDIRECTIONALFLOWRECORD(Base):
    __tablename__ = 'UNIDIRECTIONALFLOWRECORD'
    __bind_key__  = 'XORCISM'

    UnidirectionalFlowRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<UNIDIRECTIONALFLOWRECORD {self.UnidirectionalFlowRecordID}>'

class UNIQUEFUNCTION(Base):
    __tablename__ = 'UNIQUEFUNCTION'
    __bind_key__  = 'XORCISM'

    UniqueFunctionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<UNIQUEFUNCTION {self.UniqueFunctionID}>'

class UNIT(Base):
    __tablename__ = 'UNIT'
    __bind_key__  = 'XORCISM'

    UnitID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<UNIT {self.UnitID}>'

class UNIXFILE(Base):
    __tablename__ = 'UNIXFILE'
    __bind_key__  = 'XORCISM'

    UnixFileID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<UNIXFILE {self.UnixFileID}>'

class UNIXNETWORKROUTEENTRY(Base):
    __tablename__ = 'UNIXNETWORKROUTEENTRY'
    __bind_key__  = 'XORCISM'

    UnixNetworkRouteEntryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<UNIXNETWORKROUTEENTRY {self.UnixNetworkRouteEntryID}>'

class UNIXPIPEOBJECT(Base):
    __tablename__ = 'UNIXPIPEOBJECT'
    __bind_key__  = 'XORCISM'

    UnixPipeObjectID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<UNIXPIPEOBJECT {self.UnixPipeObjectID}>'

class UNIXPROCESS(Base):
    __tablename__ = 'UNIXPROCESS'
    __bind_key__  = 'XORCISM'

    UnixProcessID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<UNIXPROCESS {self.UnixProcessID}>'

class UNIXUSERACCOUNT(Base):
    __tablename__ = 'UNIXUSERACCOUNT'
    __bind_key__  = 'XORCISM'

    UnixUserAccountID = Column(Integer, primary_key=True)
    AccountID = Column(Integer)

    def __repr__(self):
        return f'<UNIXUSERACCOUNT {self.UnixUserAccountID}>'

class UNIXVOLUME(Base):
    __tablename__ = 'UNIXVOLUME'
    __bind_key__  = 'XORCISM'

    UnixVolumeID = Column(Integer, primary_key=True)
    VolumeObjectID = Column(Integer)

    def __repr__(self):
        return f'<UNIXVOLUME {self.UnixVolumeID}>'

class URGENCY(Base):
    __tablename__ = 'URGENCY'
    __bind_key__  = 'XORCISM'

    UrgencyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<URGENCY {self.UrgencyID}>'

class URIOBJECT(Base):
    __tablename__ = 'URIOBJECT'
    __bind_key__  = 'XORCISM'

    URIObjectID = Column(Integer, primary_key=True)
    URIValue = Column(Text)
    URITypeID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<URIOBJECT {self.URIObjectID}>'

class URITYPE(Base):
    __tablename__ = 'URITYPE'
    __bind_key__  = 'XORCISM'

    URITypeID = Column(Integer, primary_key=True)
    URITypeName = Column(Text)
    URITypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<URITYPE {self.URITypeID}>'

class URL(Base):
    __tablename__ = 'URL'
    __bind_key__  = 'XORCISM'

    URLID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer)

    def __repr__(self):
        return f'<URL {self.URLID}>'

class URLHISTORY(Base):
    __tablename__ = 'URLHISTORY'
    __bind_key__  = 'XORCISM'

    URLHistoryID = Column(Integer, primary_key=True)
    URLHistoryGUID = Column(Text)
    BrowserToolInformationID = Column(Integer)
    ToolInformationGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<URLHISTORY {self.URLHistoryID}>'

class URLHISTORYENTRIES(Base):
    __tablename__ = 'URLHISTORYENTRIES'
    __bind_key__  = 'XORCISM'

    URLHistoryEntriesID = Column(Integer, primary_key=True)
    URLHistoryID = Column(Integer)
    URLHistoryGUID = Column(Text)
    URLHistoryEntryID = Column(Integer)
    URLHistoryEntryGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<URLHISTORYENTRIES {self.URLHistoryEntriesID}>'

class URLHISTORYENTRY(Base):
    __tablename__ = 'URLHISTORYENTRY'
    __bind_key__  = 'XORCISM'

    URLHistoryEntryID = Column(Integer, primary_key=True)
    URLHistoryEntryGUID = Column(Text)
    URIObjectID = Column(Integer)
    HostnameID = Column(Integer)
    Referrer_URL = Column(Integer)
    Page_Title = Column(Text)
    User_Profile_Name = Column(Text)
    Visit_Count = Column(Integer)
    Manually_Entered_Count = Column(Integer)
    Modification_DateTime = Column(Text)
    Expiration_DateTime = Column(Text)
    First_Visit_DateTime = Column(Text)
    Last_Visit_DateTime = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    CollectionMethoID = Column(Integer)

    def __repr__(self):
        return f'<URLHISTORYENTRY {self.URLHistoryEntryID}>'

class USAGETYPE(Base):
    __tablename__ = 'USAGETYPE'
    __bind_key__  = 'XORCISM'

    UsageTypeID = Column(Integer, primary_key=True)
    TypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<USAGETYPE {self.UsageTypeID}>'

class USECASE(Base):
    __tablename__ = 'USECASE'
    __bind_key__  = 'XORCISM'

    UseCaseID = Column(Integer, primary_key=True)
    UseCaseGUID = Column(Text)
    UseCaseDescription = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<USECASE {self.UseCaseID}>'

class USECASECATEGORY(Base):
    __tablename__ = 'USECASECATEGORY'
    __bind_key__  = 'XORCISM'

    UseCaseCategoryID = Column(Integer, primary_key=True)
    UseCaseCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    UseCasecategoryName = Column(Text)
    UseCaseCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<USECASECATEGORY {self.UseCaseCategoryID}>'

class USECASEFORBUSINESSRISK(Base):
    __tablename__ = 'USECASEFORBUSINESSRISK'
    __bind_key__  = 'XORCISM'

    BusinessRiskUseCaseID = Column(Integer, primary_key=True)
    BusinessRiskUseCaseGUID = Column(Text)
    UseCaseID = Column(Integer, nullable=False)
    UseCaseGUID = Column(Text)
    BusinessRiskID = Column(Integer, nullable=False)
    BusinessRiskGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<USECASEFORBUSINESSRISK {self.BusinessRiskUseCaseID}>'

class USECASEFORREGULATORYRISK(Base):
    __tablename__ = 'USECASEFORREGULATORYRISK'
    __bind_key__  = 'XORCISM'

    RegulatoryRiskUseCaseID = Column(Integer, primary_key=True)
    RegulatoryRiskUseCaseGUID = Column(Text)
    UseCaseID = Column(Integer, nullable=False)
    UseCaseGUID = Column(Text)
    RegulatoryRiskID = Column(Integer, nullable=False)
    RegulatoryRiskGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<USECASEFORREGULATORYRISK {self.RegulatoryRiskUseCaseID}>'

class USER(Base):
    __tablename__ = 'USER'
    __bind_key__  = 'XORCISM'

    UserID = Column(Integer, primary_key=True)
    UserGUID = Column(Text)
    UserName = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromdate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<USER {self.UserID}>'

class USERACCOUNT(Base):
    __tablename__ = 'USERACCOUNT'
    __bind_key__  = 'XORCISM'

    UserAccountID = Column(Integer, primary_key=True)
    AccountID = Column(Integer)
    UserID = Column(Text)
    UserAccountACL = Column(Integer)
    UserAccountTypeID = Column(Integer)
    UserAccountTypeName = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<USERACCOUNT {self.UserAccountID}>'

class USERACCOUNTTYPE(Base):
    __tablename__ = 'USERACCOUNTTYPE'
    __bind_key__  = 'XORCISM'

    UserAccountTypeID = Column(Integer, primary_key=True)
    UserAccountTypeGUID = Column(Text)
    UserAccountTypeName = Column(Text)
    UserAccountTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<USERACCOUNTTYPE {self.UserAccountTypeID}>'

class USERACTIONNAME(Base):
    __tablename__ = 'USERACTIONNAME'
    __bind_key__  = 'XORCISM'

    UserActionNameID = Column(Integer, primary_key=True)
    UserActionNameName = Column(Text, nullable=False)
    UserActionNameDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<USERACTIONNAME {self.UserActionNameID}>'

class USERAGENT(Base):
    __tablename__ = 'USERAGENT'
    __bind_key__  = 'XORCISM'

    UserAgentID = Column(Integer, primary_key=True)
    UserAgentGUID = Column(Text)

    def __repr__(self):
        return f'<USERAGENT {self.UserAgentID}>'

class USERAGENTBLACKLIST(Base):
    __tablename__ = 'USERAGENTBLACKLIST'
    __bind_key__  = 'XORCISM'

    UserAgentBlacklistID = Column(Integer, primary_key=True)
    UserAgentBlacklistGUID = Column(Text)
    UserAgentBlacklistName = Column(Text)
    UserAgentBlacklistDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<USERAGENTBLACKLIST {self.UserAgentBlacklistID}>'

class USERAGENTCATEGORY(Base):
    __tablename__ = 'USERAGENTCATEGORY'
    __bind_key__  = 'XORCISM'

    UserAgentCategoryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<USERAGENTCATEGORY {self.UserAgentCategoryID}>'

class USERSESSION(Base):
    __tablename__ = 'USERSESSION'
    __bind_key__  = 'XORCISM'

    UserSessionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<USERSESSION {self.UserSessionID}>'

class VALIDITY(Base):
    __tablename__ = 'VALIDITY'
    __bind_key__  = 'XORCISM'

    ValidityID = Column(Integer, primary_key=True)
    Not_Before = Column(Text)
    Not_After = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<VALIDITY {self.ValidityID}>'

class VALUE(Base):
    __tablename__ = 'VALUE'
    __bind_key__  = 'XORCISM'

    ValueID = Column(Integer, primary_key=True)
    ValueValue = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<VALUE {self.ValueID}>'

class VALUEBLACKLIST(Base):
    __tablename__ = 'VALUEBLACKLIST'
    __bind_key__  = 'XORCISM'

    ValueBlacklistID = Column(Integer, primary_key=True)
    ValueID = Column(Integer)

    def __repr__(self):
        return f'<VALUEBLACKLIST {self.ValueBlacklistID}>'

class VALUEGROUP(Base):
    __tablename__ = 'VALUEGROUP'
    __bind_key__  = 'XORCISM'

    ValueGroupID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<VALUEGROUP {self.ValueGroupID}>'

class VALUEMAPPING(Base):
    __tablename__ = 'VALUEMAPPING'
    __bind_key__  = 'XORCISM'

    ValueMappingID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<VALUEMAPPING {self.ValueMappingID}>'

class VALUEWHITELIST(Base):
    __tablename__ = 'VALUEWHITELIST'
    __bind_key__  = 'XORCISM'

    ValueWhitelistID = Column(Integer, primary_key=True)
    ValueID = Column(Integer)

    def __repr__(self):
        return f'<VALUEWHITELIST {self.ValueWhitelistID}>'

class VARIABLE(Base):
    __tablename__ = 'VARIABLE'
    __bind_key__  = 'XORCISM'

    VariableID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<VARIABLE {self.VariableID}>'

class VERSION(Base):
    __tablename__ = 'VERSION'
    __bind_key__  = 'XORCISM'

    VersionID = Column(Integer, primary_key=True)
    VersionValue = Column(Text)
    VersionDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<VERSION {self.VersionID}>'

class VIEWPORT(Base):
    __tablename__ = 'VIEWPORT'
    __bind_key__  = 'XORCISM'

    ViewPortID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<VIEWPORT {self.ViewPortID}>'

class VOCABULARY(Base):
    __tablename__ = 'VOCABULARY'
    __bind_key__  = 'XORCISM'

    VocabularyID = Column(Integer, primary_key=True)
    VocabularyGUID = Column(Text)
    VocabularyName = Column(Text, nullable=False)
    VocabularyDescription = Column(Text)
    VocabularyVersion = Column(Text)
    VocabularyReference = Column(Text)
    DateModified = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<VOCABULARY {self.VocabularyID}>'

class VOCABULARYCATEGORIES(Base):
    __tablename__ = 'VOCABULARYCATEGORIES'
    __bind_key__  = 'XORCISM'

    VocabularyCategoriesID = Column(Integer, primary_key=True)
    VocabularyID = Column(Integer)
    VocabularyCategoryID = Column(Integer)
    CategoryID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<VOCABULARYCATEGORIES {self.VocabularyCategoriesID}>'

class VOCABULARYCATEGORY(Base):
    __tablename__ = 'VOCABULARYCATEGORY'
    __bind_key__  = 'XORCISM'

    VocabularyCategoryID = Column(Integer, primary_key=True)
    VocabularyCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    VocabularyCategoryName = Column(Text)
    VocabularyCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<VOCABULARYCATEGORY {self.VocabularyCategoryID}>'

class VOCABULARYCHANGERECORD(Base):
    __tablename__ = 'VOCABULARYCHANGERECORD'
    __bind_key__  = 'XORCISM'

    VocabularyChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<VOCABULARYCHANGERECORD {self.VocabularyChangeRecordID}>'

class VOCABULARYDESCRIPTION(Base):
    __tablename__ = 'VOCABULARYDESCRIPTION'
    __bind_key__  = 'XORCISM'

    VocabularyDescriptionID = Column(Integer, primary_key=True)
    VocabularyDescribedID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<VOCABULARYDESCRIPTION {self.VocabularyDescriptionID}>'

class VOCABULARYREFERENCE(Base):
    __tablename__ = 'VOCABULARYREFERENCE'
    __bind_key__  = 'XORCISM'

    VocabularyID = Column(Integer, primary_key=True)
    ReferenceID = Column(Integer, nullable=False)
    VocabularyReferenceDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<VOCABULARYREFERENCE {self.VocabularyID}>'

class VOCABULARYTAG(Base):
    __tablename__ = 'VOCABULARYTAG'
    __bind_key__  = 'XORCISM'

    VocabularyTagID = Column(Integer, primary_key=True)
    VocabularyTaggedID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocabularyID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)

    def __repr__(self):
        return f'<VOCABULARYTAG {self.VocabularyTagID}>'

class VOCABULARYVERSION(Base):
    __tablename__ = 'VOCABULARYVERSION'
    __bind_key__  = 'XORCISM'

    VocabularyVersionID = Column(Integer, primary_key=True)
    VocabularyVersionGUID = Column(Text)
    VocabularyID = Column(Integer, nullable=False)
    VocabularyGUID = Column(Text)
    VersionID = Column(Integer, nullable=False)
    ChangeLog = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<VOCABULARYVERSION {self.VocabularyVersionID}>'

class VOLUMEOBJECT(Base):
    __tablename__ = 'VOLUMEOBJECT'
    __bind_key__  = 'XORCISM'

    VolumeObjectID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<VOLUMEOBJECT {self.VolumeObjectID}>'

class VULNERABLECONFIGURATION(Base):
    __tablename__ = 'VULNERABLECONFIGURATION'
    __bind_key__  = 'XORCISM'

    VulnerableConfigurationID = Column(Integer, primary_key=True)
    VulnerabilityID = Column(Integer)
    ConfigurationOrder = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<VULNERABLECONFIGURATION {self.VulnerableConfigurationID}>'

class VULNERABLECONFIGURATIONCPE(Base):
    __tablename__ = 'VULNERABLECONFIGURATIONCPE'
    __bind_key__  = 'XORCISM'

    VulnerableConfigurationCPEID = Column(Integer, primary_key=True)
    VulnerableConfigurationID = Column(Integer)
    LogicalTestLevel = Column(Integer)
    LogicalTestLevelOrder = Column(Integer)
    CPELogicalTestID = Column(Integer)
    CPEID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<VULNERABLECONFIGURATIONCPE {self.VulnerableConfigurationCPEID}>'

class WAITABLETIMERTYPE(Base):
    __tablename__ = 'WAITABLETIMERTYPE'
    __bind_key__  = 'XORCISM'

    WaitableTimerTypeID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WAITABLETIMERTYPE {self.WaitableTimerTypeID}>'

class WAITABLETIMERTYPEENUM(Base):
    __tablename__ = 'WAITABLETIMERTYPEENUM'
    __bind_key__  = 'XORCISM'

    WaitaibleTimerTypeEnumID = Column(Integer, primary_key=True)
    WaitaibleTimerTypeName = Column(Text, nullable=False)
    WaitableTimerTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<WAITABLETIMERTYPEENUM {self.WaitaibleTimerTypeEnumID}>'

class WAIVER(Base):
    __tablename__ = 'WAIVER'
    __bind_key__  = 'XORCISM'

    WaiverID = Column(Integer, primary_key=True)
    WaiverName = Column(Text)
    WaiverDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WAIVER {self.WaiverID}>'

class WAIVERREASON(Base):
    __tablename__ = 'WAIVERREASON'
    __bind_key__  = 'XORCISM'

    WaiverReasonID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WAIVERREASON {self.WaiverReasonID}>'

class WARNING(Base):
    __tablename__ = 'WARNING'
    __bind_key__  = 'XORCISM'

    WarningID = Column(Integer, primary_key=True)
    WarningText = Column(Text, nullable=False)
    lang = Column(Text)
    WarningCategoryID = Column(Integer)

    def __repr__(self):
        return f'<WARNING {self.WarningID}>'

class WARNINGCATEGORY(Base):
    __tablename__ = 'WARNINGCATEGORY'
    __bind_key__  = 'XORCISM'

    WarningCategoryID = Column(Integer, primary_key=True)
    WarningCategoryName = Column(Text, nullable=False)
    WarningCategoryMeaning = Column(Text)
    VocabularyID = Column(Integer)
    lang = Column(Text)

    def __repr__(self):
        return f'<WARNINGCATEGORY {self.WarningCategoryID}>'

class WASC(Base):
    __tablename__ = 'WASC'
    __bind_key__  = 'XORCISM'

    WASCID = Column(Integer, primary_key=True)
    WASCThreatType = Column(Text, nullable=False)
    WASCRefID = Column(Text, nullable=False)
    WASCName = Column(Text)
    WASCDescription = Column(Text)
    WASCExample = Column(Text)
    WASCRefURL = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WASC {self.WASCID}>'

class WASCCWE(Base):
    __tablename__ = 'WASCCWE'
    __bind_key__  = 'XORCISM'

    WASCCWEID = Column(Integer, primary_key=True)
    WASCID = Column(Integer, nullable=False)
    WASCRefID = Column(Text)
    CWEID = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WASCCWE {self.WASCCWEID}>'

class WASCFORCAPEC(Base):
    __tablename__ = 'WASCFORCAPEC'
    __bind_key__  = 'XORCISM'

    WASCForCAPECID = Column(Integer, primary_key=True)
    WASCID = Column(Integer, nullable=False)
    WASCRefID = Column(Text)
    AttackPatternID = Column(Integer)
    capec_id = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WASCFORCAPEC {self.WASCForCAPECID}>'

class WASCREFERENCE(Base):
    __tablename__ = 'WASCREFERENCE'
    __bind_key__  = 'XORCISM'

    WASCReferenceID = Column(Integer, primary_key=True)
    WASCID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WASCREFERENCE {self.WASCReferenceID}>'

class WASCTHREATTYPE(Base):
    __tablename__ = 'WASCTHREATTYPE'
    __bind_key__  = 'XORCISM'

    WASCThreatTypeID = Column(Integer, primary_key=True)
    ThreatTypeID = Column(Integer, nullable=False)
    WASCID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<WASCTHREATTYPE {self.WASCThreatTypeID}>'

class WEAKNESS(Base):
    __tablename__ = 'WEAKNESS'
    __bind_key__  = 'XORCISM'

    WeaknessID = Column(Integer, primary_key=True)
    WeaknessGUID = Column(Text)
    CWEID = Column(Text)
    WeaknessName = Column(Text)
    WeaknessDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WEAKNESS {self.WeaknessID}>'

class WEAKNESSCWE(Base):
    __tablename__ = 'WEAKNESSCWE'
    __bind_key__  = 'XORCISM'

    WeaknessCWEID = Column(Integer, primary_key=True)
    WeaknessCWEGUID = Column(Text)
    WeaknessID = Column(Integer, nullable=False)
    WeaknessGUID = Column(Text)
    CWEID = Column(Text)
    WeaknessCWEDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WEAKNESSCWE {self.WeaknessCWEID}>'

class WHOISCHANGERECORD(Base):
    __tablename__ = 'WHOISCHANGERECORD'
    __bind_key__  = 'XORCISM'

    WhoisChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WHOISCHANGERECORD {self.WhoisChangeRecordID}>'

class WHOISOBJECT(Base):
    __tablename__ = 'WHOISOBJECT'
    __bind_key__  = 'XORCISM'

    WhoisObjectID = Column(Integer, primary_key=True)
    WhoisObjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WHOISOBJECT {self.WhoisObjectID}>'

class WORD(Base):
    __tablename__ = 'WORD'
    __bind_key__  = 'XORCISM'

    WordID = Column(Integer, primary_key=True)
    WordGUID = Column(Text)
    WordValue = Column(Text)
    LocaleID = Column(Integer)
    WordDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WORD {self.WordID}>'

class WORDBLACKLIST(Base):
    __tablename__ = 'WORDBLACKLIST'
    __bind_key__  = 'XORCISM'

    WordBlacklistID = Column(Integer, primary_key=True)
    WordListID = Column(Integer)

    def __repr__(self):
        return f'<WORDBLACKLIST {self.WordBlacklistID}>'

class WORDFILE(Base):
    __tablename__ = 'WORDFILE'
    __bind_key__  = 'XORCISM'

    WordFileID = Column(Integer, primary_key=True)
    FileID = Column(Integer)

    def __repr__(self):
        return f'<WORDFILE {self.WordFileID}>'

class WORDLIST(Base):
    __tablename__ = 'WORDLIST'
    __bind_key__  = 'XORCISM'

    WordListID = Column(Integer, primary_key=True)
    WordListGUID = Column(Text)
    VersionID = Column(Integer)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WORDLIST {self.WordListID}>'

class WORDLISTCATEGORY(Base):
    __tablename__ = 'WORDLISTCATEGORY'
    __bind_key__  = 'XORCISM'

    WordListCategoryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WORDLISTCATEGORY {self.WordListCategoryID}>'

class WORDLISTWORDS(Base):
    __tablename__ = 'WORDLISTWORDS'
    __bind_key__  = 'XORCISM'

    WordListWordID = Column(Integer, primary_key=True)
    WordListID = Column(Integer, nullable=False)
    WordID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)

    def __repr__(self):
        return f'<WORDLISTWORDS {self.WordListWordID}>'

class WORDWHITELIST(Base):
    __tablename__ = 'WORDWHITELIST'
    __bind_key__  = 'XORCISM'

    WordWhitelistID = Column(Integer, primary_key=True)
    WordListID = Column(Integer)

    def __repr__(self):
        return f'<WORDWHITELIST {self.WordWhitelistID}>'

class WORKINGHOURS(Base):
    __tablename__ = 'WORKINGHOURS'
    __bind_key__  = 'XORCISM'

    WorkingHoursID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WORKINGHOURS {self.WorkingHoursID}>'

class X509CERTIFICATE(Base):
    __tablename__ = 'X509CERTIFICATE'
    __bind_key__  = 'XORCISM'

    X509CertificateID = Column(Integer, primary_key=True)
    X509CertificateGUID = Column(Text)
    CertificateID = Column(Integer)
    Version = Column(Integer)
    Serial_Number = Column(Text)
    Signature_Algorithm = Column(Text)
    EncryptionID = Column(Integer)
    Issuer = Column(Text)
    IssuerOrganisationID = Column(Integer)
    ValidityID = Column(Integer)
    Subject = Column(Text)
    SubjectOrganisationID = Column(Integer)
    SubjectPersonID = Column(Integer)
    Subject_Public_Key = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<X509CERTIFICATE {self.X509CertificateID}>'

class X509CERTIFICATEACCESSRECORD(Base):
    __tablename__ = 'X509CERTIFICATEACCESSRECORD'
    __bind_key__  = 'XORCISM'

    X509CertificateAccessRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<X509CERTIFICATEACCESSRECORD {self.X509CertificateAccessRecordID}>'

class X509CERTIFICATECHANGERECORD(Base):
    __tablename__ = 'X509CERTIFICATECHANGERECORD'
    __bind_key__  = 'XORCISM'

    X509CertificateChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<X509CERTIFICATECHANGERECORD {self.X509CertificateChangeRecordID}>'

class X509CERTIFICATENONSTANDARDEXTENSION(Base):
    __tablename__ = 'X509CERTIFICATENONSTANDARDEXTENSION'
    __bind_key__  = 'XORCISM'

    X509CertificateNonStandardExtensionID = Column(Integer, primary_key=True)
    X509CertificateID = Column(Integer, nullable=False)
    X509NonStandardExtensionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<X509CERTIFICATENONSTANDARDEXTENSION {self.X509CertificateNonStandardExtensionID}>'

class X509CERTIFICATEOBJECT(Base):
    __tablename__ = 'X509CERTIFICATEOBJECT'
    __bind_key__  = 'XORCISM'

    X509CertificateObjectID = Column(Integer, primary_key=True)
    X509CertificateID = Column(Integer, nullable=False)
    X509CertificateGUID = Column(Text)
    X509SignatureID = Column(Integer, nullable=False)
    X509SignatureGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<X509CERTIFICATEOBJECT {self.X509CertificateObjectID}>'

class X509CERTIFICATESTANDARDEXTENSION(Base):
    __tablename__ = 'X509CERTIFICATESTANDARDEXTENSION'
    __bind_key__  = 'XORCISM'

    X509CertificateStandardExtensionID = Column(Integer, primary_key=True)
    X509CertificateID = Column(Integer, nullable=False)
    X509CertificateGUID = Column(Text)
    X509V3ExtensionID = Column(Integer, nullable=False)
    X509V3ExtensionGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<X509CERTIFICATESTANDARDEXTENSION {self.X509CertificateStandardExtensionID}>'

class X509NONSTANDARDEXTENSION(Base):
    __tablename__ = 'X509NONSTANDARDEXTENSION'
    __bind_key__  = 'XORCISM'

    X509NonStandardExtensionID = Column(Integer, primary_key=True)
    X509NonStandardExtensionGUID = Column(Text)
    Netscape_Comment = Column(Text)
    Netscape_Certificate_Type = Column(Text)
    Old_Authority_Key_Identifier = Column(Text)
    Old_Primary_Key_Attributes = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<X509NONSTANDARDEXTENSION {self.X509NonStandardExtensionID}>'

class X509SIGNATURE(Base):
    __tablename__ = 'X509SIGNATURE'
    __bind_key__  = 'XORCISM'

    X509SignatureID = Column(Integer, primary_key=True)
    X509SignatureGUID = Column(Text)
    SignatureID = Column(Integer)
    Signature_Algorithm = Column(Text)
    EncryptionID = Column(Integer)
    Signature = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    TrustLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<X509SIGNATURE {self.X509SignatureID}>'

class X509V3EXTENSION(Base):
    __tablename__ = 'X509V3EXTENSION'
    __bind_key__  = 'XORCISM'

    X509V3ExtensionID = Column(Integer, primary_key=True)
    X509V3ExtensionGUID = Column(Text)
    Basic_Constraints = Column(Text)
    Name_Constraints = Column(Text)
    Policy_Constraints = Column(Text)
    Key_Usage = Column(Text)
    Extended_Key_Usage = Column(Text)
    Subject_Key_Identifier = Column(Text)
    Authority_Key_Identifier = Column(Text)
    Subject_Alternative_Name = Column(Text)
    Issuer_Alternative_Name = Column(Text)
    Subject_Directory_Attributes = Column(Text)
    CRL_Distribution_Points = Column(Text)
    Inhibit_Any_Policy = Column(Integer)
    Private_Key_Usage_Period = Column(Integer)
    Certificate_Policies = Column(Text)
    Policy_Mappings = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<X509V3EXTENSION {self.X509V3ExtensionID}>'

class X509V3EXTENSIONACCESSRECORD(Base):
    __tablename__ = 'X509V3EXTENSIONACCESSRECORD'
    __bind_key__  = 'XORCISM'

    X509V3ExtensionAccessRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<X509V3EXTENSIONACCESSRECORD {self.X509V3ExtensionAccessRecordID}>'

class X509V3EXTENSIONPOLICYTERM(Base):
    __tablename__ = 'X509V3EXTENSIONPOLICYTERM'
    __bind_key__  = 'XORCISM'

    X509V3ExtensionPolicyTermID = Column(Integer, primary_key=True)
    X509V3ExtensionID = Column(Integer, nullable=False)
    PolicyTermID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<X509V3EXTENSIONPOLICYTERM {self.X509V3ExtensionPolicyTermID}>'

class ZONE(Base):
    __tablename__ = 'ZONE'
    __bind_key__  = 'XORCISM'

    ZoneID = Column(Integer, primary_key=True)
    ZoneGUID = Column(Text)
    ZoneName = Column(Text)
    ZoneDescription = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ZONE {self.ZoneID}>'

class ZONECLASSIFICATION(Base):
    __tablename__ = 'ZONECLASSIFICATION'
    __bind_key__  = 'XORCISM'

    ZoneClassificationID = Column(Integer, primary_key=True)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ZONECLASSIFICATION {self.ZoneClassificationID}>'

class ZONEDESCRIPTION(Base):
    __tablename__ = 'ZONEDESCRIPTION'
    __bind_key__  = 'XORCISM'

    ZoneDescriptionID = Column(Integer, primary_key=True)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ZONEDESCRIPTION {self.ZoneDescriptionID}>'

class ZONERESTRICTION(Base):
    __tablename__ = 'ZONERESTRICTION'
    __bind_key__  = 'XORCISM'

    ZoneRestrictionID = Column(Integer, primary_key=True)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ZONERESTRICTION {self.ZoneRestrictionID}>'

class aspnet_Applications(Base):
    __tablename__ = 'aspnet_Applications'
    __bind_key__  = 'XORCISM'

    ApplicationName = Column(Text, primary_key=True)
    LoweredApplicationName = Column(Text, nullable=False)
    ApplicationId = Column(Text, nullable=False)
    Description = Column(Text)

    def __repr__(self):
        return f'<aspnet_Applications {self.ApplicationName}>'

class aspnet_Membership(Base):
    __tablename__ = 'aspnet_Membership'
    __bind_key__  = 'XORCISM'

    ApplicationId = Column(Text, primary_key=True)
    UserId = Column(Text, nullable=False)
    Password = Column(Text, nullable=False)
    PasswordFormat = Column(Integer, nullable=False)
    PasswordSalt = Column(Text, nullable=False)
    MobilePIN = Column(Text)
    Email = Column(Text)
    LoweredEmail = Column(Text)
    PasswordQuestion = Column(Text)
    PasswordAnswer = Column(Text)
    IsApproved = Column(Integer, nullable=False)
    IsLockedOut = Column(Integer, nullable=False)
    CreateDate = Column(Text, nullable=False)
    LastLoginDate = Column(Text, nullable=False)
    LastPasswordChangedDate = Column(Text, nullable=False)
    LastLockoutDate = Column(Text, nullable=False)
    FailedPasswordAttemptCount = Column(Integer, nullable=False)
    FailedPasswordAttemptWindowStart = Column(Text, nullable=False)
    FailedPasswordAnswerAttemptCount = Column(Integer, nullable=False)
    FailedPasswordAnswerAttemptWindowStart = Column(Text, nullable=False)
    Comment = Column(Text)

    def __repr__(self):
        return f'<aspnet_Membership {self.ApplicationId}>'

class aspnet_Paths(Base):
    __tablename__ = 'aspnet_Paths'
    __bind_key__  = 'XORCISM'

    ApplicationId = Column(Text, primary_key=True)
    PathId = Column(Text, nullable=False)
    Path = Column(Text, nullable=False)
    LoweredPath = Column(Text, nullable=False)

    def __repr__(self):
        return f'<aspnet_Paths {self.ApplicationId}>'

class aspnet_PersonalizationAllUsers(Base):
    __tablename__ = 'aspnet_PersonalizationAllUsers'
    __bind_key__  = 'XORCISM'

    PathId = Column(Text, primary_key=True)
    PageSettings = Column(LargeBinary, nullable=False)
    LastUpdatedDate = Column(Text, nullable=False)

    def __repr__(self):
        return f'<aspnet_PersonalizationAllUsers {self.PathId}>'

class aspnet_PersonalizationPerUser(Base):
    __tablename__ = 'aspnet_PersonalizationPerUser'
    __bind_key__  = 'XORCISM'

    Id = Column(Text, primary_key=True)
    PathId = Column(Text)
    UserId = Column(Text)
    PageSettings = Column(LargeBinary, nullable=False)
    LastUpdatedDate = Column(Text, nullable=False)

    def __repr__(self):
        return f'<aspnet_PersonalizationPerUser {self.Id}>'

class aspnet_Profile(Base):
    __tablename__ = 'aspnet_Profile'
    __bind_key__  = 'XORCISM'

    UserId = Column(Text, primary_key=True)
    PropertyNames = Column(Text, nullable=False)
    PropertyValuesString = Column(Text, nullable=False)
    PropertyValuesBinary = Column(LargeBinary, nullable=False)
    LastUpdatedDate = Column(Text, nullable=False)

    def __repr__(self):
        return f'<aspnet_Profile {self.UserId}>'

class aspnet_Roles(Base):
    __tablename__ = 'aspnet_Roles'
    __bind_key__  = 'XORCISM'

    ApplicationId = Column(Text, primary_key=True)
    RoleId = Column(Text, nullable=False)
    RoleName = Column(Text, nullable=False)
    LoweredRoleName = Column(Text, nullable=False)
    Description = Column(Text)

    def __repr__(self):
        return f'<aspnet_Roles {self.ApplicationId}>'

class aspnet_SchemaVersions(Base):
    __tablename__ = 'aspnet_SchemaVersions'
    __bind_key__  = 'XORCISM'

    Feature = Column(Text, primary_key=True)
    CompatibleSchemaVersion = Column(Text, nullable=False)
    IsCurrentVersion = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<aspnet_SchemaVersions {self.Feature}>'

class aspnet_Users(Base):
    __tablename__ = 'aspnet_Users'
    __bind_key__  = 'XORCISM'

    ApplicationId = Column(Text, primary_key=True)
    UserId = Column(Text, nullable=False)
    UserName = Column(Text, nullable=False)
    LoweredUserName = Column(Text, nullable=False)
    MobileAlias = Column(Text)
    IsAnonymous = Column(Integer, nullable=False)
    LastActivityDate = Column(Text, nullable=False)

    def __repr__(self):
        return f'<aspnet_Users {self.ApplicationId}>'

class aspnet_UsersInRoles(Base):
    __tablename__ = 'aspnet_UsersInRoles'
    __bind_key__  = 'XORCISM'

    UserId = Column(Text, primary_key=True)
    RoleId = Column(Text, nullable=False)

    def __repr__(self):
        return f'<aspnet_UsersInRoles {self.UserId}>'

class aspnet_WebEvent_Events(Base):
    __tablename__ = 'aspnet_WebEvent_Events'
    __bind_key__  = 'XORCISM'

    EventId = Column(Text, primary_key=True)
    EventTimeUtc = Column(Text, nullable=False)
    EventTime = Column(Text, nullable=False)
    EventType = Column(Text, nullable=False)
    EventSequence = Column(Text, nullable=False)
    EventOccurrence = Column(Text, nullable=False)
    EventCode = Column(Integer, nullable=False)
    EventDetailCode = Column(Integer, nullable=False)
    Message = Column(Text)
    ApplicationPath = Column(Text)
    ApplicationVirtualPath = Column(Text)
    MachineName = Column(Text, nullable=False)
    RequestUrl = Column(Text)
    ExceptionType = Column(Text)
    Details = Column(Text)

    def __repr__(self):
        return f'<aspnet_WebEvent_Events {self.EventId}>'


# ── Threat models ──────────────────────────────────────────────────────────────
class THREATMODEL(Base):
    __tablename__ = 'THREATMODEL'
    __bind_key__ = 'XORCISM'

    ThreatModelID = Column(Integer, primary_key=True)
    ThreatModelGUID = Column(Text)
    ThreatModelName = Column(Text)
    Description = Column(Text)
    Methodology = Column(Text)          # STRIDE / PASTA / DREAD / Attack Tree / LINDDUN / VAST / Other
    Status = Column(Text)               # Draft / In Review / Approved / Archived
    Scope = Column(Text)
    RiskLevel = Column(Text)            # Critical / High / Medium / Low
    Owner = Column(Text)
    CreatedDate = Column(Text)
    VocabularyID = Column(Integer)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<THREATMODEL {self.ThreatModelID}>'


class THREATMODELASSET(Base):
    __tablename__ = 'THREATMODELASSET'
    __bind_key__ = 'XORCISM'

    ThreatModelAssetID = Column(Integer, primary_key=True)
    ThreatModelID = Column(Integer)
    AssetID = Column(Integer)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<THREATMODELASSET {self.ThreatModelAssetID}>'


class THREATMODELTHREAT(Base):
    __tablename__ = 'THREATMODELTHREAT'
    __bind_key__ = 'XORCISM'

    ThreatModelThreatID = Column(Integer, primary_key=True)
    ThreatModelID = Column(Integer)
    Title = Column(Text)
    STRIDECategory = Column(Text)       # Spoofing / Tampering / Repudiation / Information Disclosure / DoS / EoP
    Description = Column(Text)
    ThreatAgentID = Column(Integer)     # -> XTHREAT.THREATAGENT
    AttackPattern = Column(Text)        # CAPEC / ATT&CK reference (free text)
    Likelihood = Column(Text)           # Very Low / Low / Moderate / High / Very High
    Impact = Column(Text)
    RiskScore = Column(Text)            # Critical / High / Medium / Low
    Status = Column(Text)               # Open / Mitigated / Accepted / Transferred
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<THREATMODELTHREAT {self.ThreatModelThreatID}>'


class THREATMODELCONTROL(Base):
    __tablename__ = 'THREATMODELCONTROL'
    __bind_key__ = 'XORCISM'

    ThreatModelControlID = Column(Integer, primary_key=True)
    ThreatModelThreatID = Column(Integer)
    ControlID = Column(Integer)         # -> XORCISM.CONTROL
    Status = Column(Text)               # Proposed / Implemented / Verified
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<THREATMODELCONTROL {self.ThreatModelControlID}>'
