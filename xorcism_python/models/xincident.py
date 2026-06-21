"""
SQLAlchemy models for XINCIDENT database
Auto-generated from SQLite schema - replaces XORCISMModel/XINCIDENT C# POCO classes
"""
from sqlalchemy import Column, Integer, Float, String, Text, LargeBinary, Boolean
from .base import Base


class INCIDENT(Base):
    __tablename__ = 'INCIDENT'
    __bind_key__  = 'XINCIDENT'

    IncidentID = Column(Integer, primary_key=True)
    IncidentName = Column(Text)
    source_id = Column(Text)
    IncidentCategoryID = Column(Integer)
    publication_status = Column(Text)
    datetime_reported = Column(Text)
    start_datetime = Column(Text)
    end_datetime = Column(Text)
    detect_datetime = Column(Text)
    confirmed = Column(Integer)
    security_compromise = Column(Text)
    exercise = Column(Integer)
    ProjectID = Column(Integer)
    exercise_name = Column(Text)
    import_datetime = Column(Text)
    BLOB = Column(Text)
    IncidentStatusID = Column(Integer)
    status = Column(Text)
    status_description = Column(Text)
    synopsis = Column(Text)
    summary = Column(Text)
    impact = Column(Text)
    confidence = Column(Text)
    notes = Column(Text)
    locations_affected = Column(Integer)
    IncidentDiscoveryMethodID = Column(Integer)
    control_failure = Column(Text)
    corrective_action = Column(Text)
    Criticity = Column(Text)
    AlternativeID = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<INCIDENT {self.IncidentID}>'

class INCIDENTCATEGORY(Base):
    __tablename__ = 'INCIDENTCATEGORY'
    __bind_key__  = 'XINCIDENT'

    IncidentCategoryID = Column(Integer, primary_key=True)
    IncidentCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    IncidentCategoryName = Column(Text, nullable=False)
    IncidentCategoryDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTCATEGORY {self.IncidentCategoryID}>'

class INCIDENTCATEGORYDESCRIPTION(Base):
    __tablename__ = 'INCIDENTCATEGORYDESCRIPTION'
    __bind_key__  = 'XINCIDENT'

    IncidentCategoryDescriptionID = Column(Integer, primary_key=True)
    IncidentCategoryID = Column(Integer, nullable=False)
    IncidentCategoryGUID = Column(Text)
    DescriptionID = Column(Integer, nullable=False)
    DescriptionGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTCATEGORYDESCRIPTION {self.IncidentCategoryDescriptionID}>'

class INCIDENTCATEGORYRACIMATRIX(Base):
    __tablename__ = 'INCIDENTCATEGORYRACIMATRIX'
    __bind_key__  = 'XINCIDENT'

    IncidentCategoryRACIMatrixID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<INCIDENTCATEGORYRACIMATRIX {self.IncidentCategoryRACIMatrixID}>'

class INCIDENTCOMPROMISE(Base):
    __tablename__ = 'INCIDENTCOMPROMISE'
    __bind_key__  = 'XINCIDENT'

    IncidentCompromiseID = Column(Integer, primary_key=True)
    IncidentCompromiseGUID = Column(Text)
    SecurityCompromise = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    documentation = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTCOMPROMISE {self.IncidentCompromiseID}>'

class INCIDENTDISCOVERYMETHOD(Base):
    __tablename__ = 'INCIDENTDISCOVERYMETHOD'
    __bind_key__  = 'XINCIDENT'

    IncidentDiscoveryMethodID = Column(Integer, primary_key=True)
    DiscoveryMethodID = Column(Integer)
    IncidentDiscoveryMethodName = Column(Text, nullable=False)
    IncidentDiscoveryMethodDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTDISCOVERYMETHOD {self.IncidentDiscoveryMethodID}>'

class INCIDENTEFFECT(Base):
    __tablename__ = 'INCIDENTEFFECT'
    __bind_key__  = 'XINCIDENT'

    IncidentEffectID = Column(Integer, primary_key=True)
    IncidentEffectGUID = Column(Text)
    PossibleEffect = Column(Text, nullable=False)
    IncidentEffectDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTEFFECT {self.IncidentEffectID}>'

class INCIDENTFORASSET(Base):
    __tablename__ = 'INCIDENTFORASSET'
    __bind_key__  = 'XINCIDENT'

    AssetIncidentID = Column(Integer, primary_key=True)
    AssetIncidentGUID = Column(Text)
    AssetID = Column(Integer, nullable=False)
    AssetGUID = Column(Text)
    AssetIncidentRelationship = Column(Text)
    AssetIncidentDescription = Column(Text)
    IncidentID = Column(Integer, nullable=False)
    IncidentGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    notes = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    Criticity = Column(Integer)
    Status = Column(Text)
    Compromised = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTFORASSET {self.AssetIncidentID}>'

class INCIDENTFORINCIDENT(Base):
    __tablename__ = 'INCIDENTFORINCIDENT'
    __bind_key__  = 'XINCIDENT'

    IncidentRefID = Column(Integer, primary_key=True)
    relationshiptype = Column(Text)
    relationshipscope = Column(Text)
    IncidentSubjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<INCIDENTFORINCIDENT {self.IncidentRefID}>'

class INCIDENTFORPERSON(Base):
    __tablename__ = 'INCIDENTFORPERSON'
    __bind_key__  = 'XINCIDENT'

    IncidentID = Column(Integer, primary_key=True)
    PersonID = Column(Integer, nullable=False)
    relationshiptype = Column(Text)
    notes = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<INCIDENTFORPERSON {self.IncidentID}>'

class INCIDENTFORTHREATCAMPAIGN(Base):
    __tablename__ = 'INCIDENTFORTHREATCAMPAIGN'
    __bind_key__  = 'XINCIDENT'

    IncidentID = Column(Integer, primary_key=True)
    CampaignID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INCIDENTFORTHREATCAMPAIGN {self.IncidentID}>'

class INCIDENTID(Base):
    __tablename__ = 'INCIDENTID'
    __bind_key__  = 'XINCIDENT'

    IncidentIDID = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    instance = Column(Text)
    restriction = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTID {self.IncidentIDID}>'

class INCIDENTIMPACT(Base):
    __tablename__ = 'INCIDENTIMPACT'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactID = Column(Integer, primary_key=True)
    IncidentID = Column(Integer, nullable=False)
    IncidentImpactRatingID = Column(Integer)
    IncidentImpactLossVarietyID = Column(Integer)
    IncidentImpactLossRatingID = Column(Integer)
    overall_amount = Column(Text)
    overall_min_amount = Column(Text)
    overall_max_amount = Column(Text)
    iso_currency_code = Column(Text)
    notes = Column(Text)
    DateCreated = Column(Text)
    BLOB = Column(Text)
    IncidentImpactAvailabilityVarietyID = Column(Integer)
    IncidentImpactAvailabilityDurationLossID = Column(Integer)
    IncidentImpactIntegrityVarietyID = Column(Integer)
    IncidentImpactConfidentialityStateID = Column(Integer)
    IncidentImpactConfidentialityVarietyID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTIMPACT {self.IncidentImpactID}>'

class INCIDENTIMPACTAVAILABILITYLOSSDURATION(Base):
    __tablename__ = 'INCIDENTIMPACTAVAILABILITYLOSSDURATION'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactAvailabilityLossDurationID = Column(Integer, primary_key=True)
    LossDuration = Column(Text, nullable=False)
    LossDurationDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTIMPACTAVAILABILITYLOSSDURATION {self.IncidentImpactAvailabilityLossDurationID}>'

class INCIDENTIMPACTAVAILABILITYVARIETY(Base):
    __tablename__ = 'INCIDENTIMPACTAVAILABILITYVARIETY'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactAvailabilityVarietyID = Column(Integer, primary_key=True)
    IncidentImpactAvailabilityVarietyName = Column(Text)
    IncidentImpactAvailabilityVarietyDescription = Column(Text)

    def __repr__(self):
        return f'<INCIDENTIMPACTAVAILABILITYVARIETY {self.IncidentImpactAvailabilityVarietyID}>'

class INCIDENTIMPACTCONFIDENTIALITYSTATE(Base):
    __tablename__ = 'INCIDENTIMPACTCONFIDENTIALITYSTATE'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactConfidentialityStateID = Column(Integer, primary_key=True)
    IncidentImpactConfidentialityStateName = Column(Text, nullable=False)
    IncidentImpactConfidentialityStateDescription = Column(Text)

    def __repr__(self):
        return f'<INCIDENTIMPACTCONFIDENTIALITYSTATE {self.IncidentImpactConfidentialityStateID}>'

class INCIDENTIMPACTCONFIDENTIALITYVARIETY(Base):
    __tablename__ = 'INCIDENTIMPACTCONFIDENTIALITYVARIETY'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactConfidentialityVarietyID = Column(Integer, primary_key=True)
    IncidentImpactConfidentialityVarietyName = Column(Text, nullable=False)
    IncidentImpactConfidentialityVarietyDescription = Column(Text)

    def __repr__(self):
        return f'<INCIDENTIMPACTCONFIDENTIALITYVARIETY {self.IncidentImpactConfidentialityVarietyID}>'

class INCIDENTIMPACTINTEGRITYVARIETY(Base):
    __tablename__ = 'INCIDENTIMPACTINTEGRITYVARIETY'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactIntegrityVarietyID = Column(Integer, primary_key=True)
    IncidentImpactIntegrityVarietyName = Column(Text, nullable=False)
    IncidentImpactIntegrityVarietyDescription = Column(Text)

    def __repr__(self):
        return f'<INCIDENTIMPACTINTEGRITYVARIETY {self.IncidentImpactIntegrityVarietyID}>'

class INCIDENTIMPACTLOSSPROPERTY(Base):
    __tablename__ = 'INCIDENTIMPACTLOSSPROPERTY'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactLossPropertyID = Column(Integer, primary_key=True)
    IncidentImpactLossPropertyName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTIMPACTLOSSPROPERTY {self.IncidentImpactLossPropertyID}>'

class INCIDENTIMPACTLOSSRATING(Base):
    __tablename__ = 'INCIDENTIMPACTLOSSRATING'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactLossRatingID = Column(Integer, primary_key=True)
    IncidentImpactLossRatingName = Column(Text, nullable=False)
    IncidentImpactLossRatingDescription = Column(Text)

    def __repr__(self):
        return f'<INCIDENTIMPACTLOSSRATING {self.IncidentImpactLossRatingID}>'

class INCIDENTIMPACTLOSSVARIETY(Base):
    __tablename__ = 'INCIDENTIMPACTLOSSVARIETY'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactLossVarietyID = Column(Integer, primary_key=True)
    IncidentImpactLossVarietyName = Column(Text, nullable=False)
    IncidentImpactLossVarietyDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTIMPACTLOSSVARIETY {self.IncidentImpactLossVarietyID}>'

class INCIDENTIMPACTRATING(Base):
    __tablename__ = 'INCIDENTIMPACTRATING'
    __bind_key__  = 'XINCIDENT'

    IncidentImpactRatingID = Column(Integer, primary_key=True)
    IncidentImpactRatingName = Column(Text, nullable=False)
    IncidentImpactRatingDescription = Column(Text)

    def __repr__(self):
        return f'<INCIDENTIMPACTRATING {self.IncidentImpactRatingID}>'

class INCIDENTINQUIRY(Base):
    __tablename__ = 'INCIDENTINQUIRY'
    __bind_key__  = 'XINCIDENT'

    IncidentIQID = Column(Integer, primary_key=True)
    IncidentInquiryIntentID = Column(Integer)
    purpose = Column(Text, nullable=False)
    CreatedDate = Column(Text)
    format = Column(Text)
    BLOB = Column(Text)
    lang = Column(Text)
    restriction = Column(Text)
    IODEFversion = Column(Text)
    formatid = Column(Text)

    def __repr__(self):
        return f'<INCIDENTINQUIRY {self.IncidentIQID}>'

class INCIDENTINQUIRYINTENT(Base):
    __tablename__ = 'INCIDENTINQUIRYINTENT'
    __bind_key__  = 'XINCIDENT'

    IncidentInquiryIntentID = Column(Integer, primary_key=True)
    PackageIntent = Column(Text, nullable=False)
    PackageIntentDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTINQUIRYINTENT {self.IncidentInquiryIntentID}>'

class INCIDENTIOC(Base):
    __tablename__ = 'INCIDENTIOC'
    __bind_key__  = 'XINCIDENT'

    IncidentIOCID = Column(Integer, primary_key=True)
    IncidentID = Column(Integer, nullable=False)
    comment = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    IncidentIOCTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INCIDENTIOC {self.IncidentIOCID}>'

class INCIDENTIOCFORTHREATCAMPAIGN(Base):
    __tablename__ = 'INCIDENTIOCFORTHREATCAMPAIGN'
    __bind_key__  = 'XINCIDENT'

    IncidentIOCID = Column(Integer, primary_key=True)
    ThreatCampaignID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INCIDENTIOCFORTHREATCAMPAIGN {self.IncidentIOCID}>'

class INCIDENTIOCTYPE(Base):
    __tablename__ = 'INCIDENTIOCTYPE'
    __bind_key__  = 'XINCIDENT'

    IncidentIOCTypeID = Column(Integer, primary_key=True)
    IndicatorTypeName = Column(Text, nullable=False)
    IndicatorTypeDocumentaion = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTIOCTYPE {self.IncidentIOCTypeID}>'

class INCIDENTIOCTYPEFORINDICATOR(Base):
    __tablename__ = 'INCIDENTIOCTYPEFORINDICATOR'
    __bind_key__  = 'XINCIDENT'

    IncidentIOCTypeID = Column(Integer, primary_key=True)
    IndicatorID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<INCIDENTIOCTYPEFORINDICATOR {self.IncidentIOCTypeID}>'

class INCIDENTREGISTRYHANDLE(Base):
    __tablename__ = 'INCIDENTREGISTRYHANDLE'
    __bind_key__  = 'XINCIDENT'

    IncidentRegistryHandleID = Column(Integer, primary_key=True)
    registry = Column(Text, nullable=False)

    def __repr__(self):
        return f'<INCIDENTREGISTRYHANDLE {self.IncidentRegistryHandleID}>'

class INCIDENTSTATUS(Base):
    __tablename__ = 'INCIDENTSTATUS'
    __bind_key__  = 'XINCIDENT'

    IncidentStatusID = Column(Integer, primary_key=True)
    IncidentStatusGUID = Column(Text)
    IncidentStatusName = Column(Text, nullable=False)
    IncidentStatusDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTSTATUS {self.IncidentStatusID}>'

class INCIDENTTIMELINE(Base):
    __tablename__ = 'INCIDENTTIMELINE'
    __bind_key__  = 'XINCIDENT'

    IncidentTimelineID = Column(Integer, primary_key=True)
    IncidentID = Column(Integer, nullable=False)
    investigationDate = Column(Text)
    incidentDate = Column(Text)
    TimetoCompromiseValue = Column(Integer)
    TimetoCompromiseUnit = Column(Text)
    TimetoExfiltrationValue = Column(Integer)
    TimetoExfiltrationUnit = Column(Text)
    TimetoDiscoveryValue = Column(Integer)
    TimetoDiscoveryUnit = Column(Text)
    TimetoContainmentValue = Column(Integer)
    TimetoContainmentUnit = Column(Text)

    def __repr__(self):
        return f'<INCIDENTTIMELINE {self.IncidentTimelineID}>'

class INCIDENTTIMELINEUNIT(Base):
    __tablename__ = 'INCIDENTTIMELINEUNIT'
    __bind_key__  = 'XINCIDENT'

    IncidentTimelineUnitID = Column(Integer, primary_key=True)
    TimeUnit = Column(Text, nullable=False)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<INCIDENTTIMELINEUNIT {self.IncidentTimelineUnitID}>'
