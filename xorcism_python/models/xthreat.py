"""
SQLAlchemy models for XTHREAT database
Auto-generated from SQLite schema - replaces XORCISMModel/XTHREAT C# POCO classes
"""
from sqlalchemy import Column, Integer, Float, String, Text, LargeBinary, Boolean
from .base import Base


class THREAT(Base):
    __tablename__ = 'THREAT'
    __bind_key__  = 'XTHREAT'

    ThreatID = Column(Integer, primary_key=True)
    ThreatGUID = Column(Text)
    ThreatName = Column(Text)
    ThreatDescription = Column(Text)
    ThreatProvenance = Column(Text)
    Criticity = Column(Integer)
    ValidFrom = Column(Text)   # date (ISO 8601, like the other dates)
    ValidUntil = Column(Text)  # date (ISO 8601)
    ConfidenceLevel = Column(Integer)
    TrustLevel = Column(Integer)
    STIXType = Column(Text)            # type d'objet STIX 2.1 (threat-actor, attack-pattern…)
    ThreatActorID = Column(Integer)    # lien THREATACTOR (relation STIX)

    def __repr__(self):
        return f'<THREAT {self.ThreatID}>'


class THREATACTION(Base):
    __tablename__ = 'THREATACTION'
    __bind_key__  = 'XTHREAT'

    ThreatActionID = Column(Integer, primary_key=True)
    ThreatActionCategoryID = Column(Integer, nullable=False)
    ThreatActionCategoryName = Column(Text)
    ThreatActionName = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    notes = Column(Text)
    target = Column(Text)
    AssetID = Column(Integer)
    PersonID = Column(Integer)
    PhysicalLocationID = Column(Integer)
    ThreatActionTargetID = Column(Integer)
    ThreatActionLocationID = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATACTION {self.ThreatActionID}>'

class THREATACTIONCATEGORY(Base):
    __tablename__ = 'THREATACTIONCATEGORY'
    __bind_key__  = 'XTHREAT'

    ThreatActionCategoryID = Column(Integer, primary_key=True)
    ThreatActionCategoryName = Column(Text, nullable=False)
    VocabularyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATACTIONCATEGORY {self.ThreatActionCategoryID}>'

class THREATACTIONFORINCIDENT(Base):
    __tablename__ = 'THREATACTIONFORINCIDENT'
    __bind_key__  = 'XTHREAT'

    IncidentThreatActionID = Column(Integer, primary_key=True)
    ThreatActionID = Column(Integer, nullable=False)
    ThreatActorID = Column(Integer, nullable=False)
    IncidentID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ThreatIntendedEffectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATACTIONFORINCIDENT {self.IncidentThreatActionID}>'

class THREATACTIONLOCATION(Base):
    __tablename__ = 'THREATACTIONLOCATION'
    __bind_key__  = 'XTHREAT'

    ThreatActionLocationID = Column(Integer, primary_key=True)
    ThreatActionLocationName = Column(Text, nullable=False)
    VocabularyID = Column(Integer, nullable=False)
    PhysicalLocationID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTIONLOCATION {self.ThreatActionLocationID}>'

class THREATACTIONLOCATIONFORTHREATACTIONCATEGORY(Base):
    __tablename__ = 'THREATACTIONLOCATIONFORTHREATACTIONCATEGORY'
    __bind_key__  = 'XTHREAT'

    ThreatActionCategoryLocationID = Column(Integer, primary_key=True)
    ThreatActionCategoryID = Column(Integer, nullable=False)
    ThreatActionLocationID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<THREATACTIONLOCATIONFORTHREATACTIONCATEGORY {self.ThreatActionCategoryLocationID}>'

class THREATACTIONTARGET(Base):
    __tablename__ = 'THREATACTIONTARGET'
    __bind_key__  = 'XTHREAT'

    ThreatActionTargetID = Column(Integer, primary_key=True)
    ThreatActionCategoryID = Column(Integer, nullable=False)
    ThreatActionTargetName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTIONTARGET {self.ThreatActionTargetID}>'

class THREATACTIONVARIETY(Base):
    __tablename__ = 'THREATACTIONVARIETY'
    __bind_key__  = 'XTHREAT'

    ThreatActionVarietyID = Column(Integer, primary_key=True)
    ThreatActionCategoryID = Column(Integer, nullable=False)
    ThreatActionVarietyName = Column(Text, nullable=False)
    ThreatActionCategoryDescription = Column(Text)
    WASCID = Column(Text)
    note = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATACTIONVARIETY {self.ThreatActionVarietyID}>'

class THREATACTIONVARIETYFORTHREATACTORTTP(Base):
    __tablename__ = 'THREATACTIONVARIETYFORTHREATACTORTTP'
    __bind_key__  = 'XTHREAT'

    ThreatActorTTPActionVarietyID = Column(Integer, primary_key=True)
    ThreatActorTTPID = Column(Integer, nullable=False)
    ThreatActionVarietyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATACTIONVARIETYFORTHREATACTORTTP {self.ThreatActorTTPActionVarietyID}>'

class THREATACTIONVECTOR(Base):
    __tablename__ = 'THREATACTIONVECTOR'
    __bind_key__  = 'XTHREAT'

    ThreatActionVectorID = Column(Integer, primary_key=True)
    ThreatActionCategoryID = Column(Integer, nullable=False)
    ThreatActionVectorName = Column(Text, nullable=False)
    VocabularyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTIONVECTOR {self.ThreatActionVectorID}>'

class THREATACTOR(Base):
    __tablename__ = 'THREATACTOR'
    __bind_key__  = 'XTHREAT'

    ThreatActorID = Column(Integer, primary_key=True)
    ThreatActorGUID = Column(Text)
    ThreatActorName = Column(Text)
    ThreatActorDescription = Column(Text)
    ActorExternal = Column(Integer)
    ActorInternal = Column(Integer)
    role = Column(Text)
    country = Column(Text)
    notes = Column(Text)
    VocabularyID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidentialityLevelID = Column(Integer)
    SourceID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    ImportanceID = Column(Integer)
    CriticalityLevelID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ThreatMotive = Column(Text)  # motivation (value from THREATMOTIVE, by vocabulary)

    def __repr__(self):
        return f'<THREATACTOR {self.ThreatActorID}>'

class THREATACTORADDRESS(Base):
    __tablename__ = 'THREATACTORADDRESS'
    __bind_key__  = 'XTHREAT'

    ThreatActorAddressID = Column(Integer, primary_key=True)
    ThreatActorID = Column(Integer)
    ThreatActorGUID = Column(Text)
    AddressID = Column(Integer)
    AddressGUID = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ConfidentialityLevelID = Column(Integer)
    SourceID = Column(Integer)
    SourceGUID = Column(Text)
    CollectionMethodID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    LastCheckedDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORADDRESS {self.ThreatActorAddressID}>'

class THREATACTORCHANGERECORD(Base):
    __tablename__ = 'THREATACTORCHANGERECORD'
    __bind_key__  = 'XTHREAT'

    ThreatActorChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATACTORCHANGERECORD {self.ThreatActorChangeRecordID}>'

class THREATACTOREMAILADDRESS(Base):
    __tablename__ = 'THREATACTOREMAILADDRESS'
    __bind_key__  = 'XTHREAT'

    ThreatActorEmailAddressID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATACTOREMAILADDRESS {self.ThreatActorEmailAddressID}>'

class THREATACTORFORINCIDENT(Base):
    __tablename__ = 'THREATACTORFORINCIDENT'
    __bind_key__  = 'XTHREAT'

    IncidentThreatActorID = Column(Integer, primary_key=True)
    IncidentID = Column(Integer, nullable=False)
    IncidentGUID = Column(Text)
    ThreatActorID = Column(Integer, nullable=False)
    ThreatActorGUID = Column(Text)
    ThreatMotiveID = Column(Integer)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text)  # nullable
    ThreatActorRoleID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    ConfidenceLevel = Column(Text)
    ValidFrom = Column(Text)   # date (ISO 8601)
    ValidUntil = Column(Text)  # date (ISO 8601)

    def __repr__(self):
        return f'<THREATACTORFORINCIDENT {self.IncidentThreatActorID}>'

class THREATACTORFORTHREATCAMPAIGN(Base):
    __tablename__ = 'THREATACTORFORTHREATCAMPAIGN'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignActorID = Column(Integer, primary_key=True)
    ThreatCampaignID = Column(Integer, nullable=False)
    ThreatCampaignGUID = Column(Text)
    ThreatActorID = Column(Integer, nullable=False)
    ThreatActorGUID = Column(Text)
    ConfidenceLevel = Column(Text)
    ConfidentialityLevelID = Column(Integer)
    notes = Column(Text)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text, nullable=False)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORFORTHREATCAMPAIGN {self.ThreatCampaignActorID}>'

class THREATACTORGROUP(Base):
    __tablename__ = 'THREATACTORGROUP'
    __bind_key__  = 'XTHREAT'

    ThreatActorGroupID = Column(Integer, primary_key=True)
    ThreatActorGroupGUID = Column(Text)
    GroupID = Column(Integer)
    ThreatActorGroupName = Column(Text)
    ThreatActorGroupDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<THREATACTORGROUP {self.ThreatActorGroupID}>'

class THREATACTORGROUPTACTIC(Base):
    __tablename__ = 'THREATACTORGROUPTACTIC'
    __bind_key__  = 'XTHREAT'

    ThreatActorGroupTacticID = Column(Integer, primary_key=True)
    ThreatActorGroupID = Column(Integer, nullable=False)
    ThreatActorGroupGUID = Column(Text)
    TacticID = Column(Integer, nullable=False)
    TacticGUID = Column(Text)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORGROUPTACTIC {self.ThreatActorGroupTacticID}>'

class THREATACTORINFRASTRUCTURE(Base):
    __tablename__ = 'THREATACTORINFRASTRUCTURE'
    __bind_key__  = 'XTHREAT'

    ThreatActorInfrastructureID = Column(Integer, primary_key=True)
    AttackerInfrastructureGUID = Column(Text)
    AttackerInfrastructureName = Column(Text, nullable=False)
    AttackerInfrastructureDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text, nullable=False)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<THREATACTORINFRASTRUCTURE {self.ThreatActorInfrastructureID}>'

class THREATACTORINFRASTRUCTUREFORTHREATACTOR(Base):
    __tablename__ = 'THREATACTORINFRASTRUCTUREFORTHREATACTOR'
    __bind_key__  = 'XTHREAT'

    ThreatActorThreatActorInfrastructureID = Column(Integer, primary_key=True)
    ThreatActorID = Column(Integer, nullable=False)
    ThreatActorInfrastructureID = Column(Integer, nullable=False)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text, nullable=False)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    notes = Column(Text)
    Description = Column(Text)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<THREATACTORINFRASTRUCTUREFORTHREATACTOR {self.ThreatActorThreatActorInfrastructureID}>'

class THREATACTORINFRASTRUCTUREFORTHREATACTORTTP(Base):
    __tablename__ = 'THREATACTORINFRASTRUCTUREFORTHREATACTORTTP'
    __bind_key__  = 'XTHREAT'

    ThreatActorTTPInfrastructureID = Column(Integer, primary_key=True)
    ThreatActorInfrastructureID = Column(Integer, nullable=False)
    ThreatActorTTPID = Column(Integer, nullable=False)
    Information_Source = Column(Text)
    ConfidenceLevel = Column(Text)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text, nullable=False)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORINFRASTRUCTUREFORTHREATACTORTTP {self.ThreatActorTTPInfrastructureID}>'

class THREATACTORPAOS(Base):
    __tablename__ = 'THREATACTORPAOS'
    __bind_key__  = 'XTHREAT'

    ThreatActorPAOSID = Column(Integer, primary_key=True)
    PlanningAndOperationalSupport = Column(Text, nullable=False)
    PAOSDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<THREATACTORPAOS {self.ThreatActorPAOSID}>'

class THREATACTORROLE(Base):
    __tablename__ = 'THREATACTORROLE'
    __bind_key__  = 'XTHREAT'

    ThreatActorRoleID = Column(Integer, primary_key=True)
    role = Column(Text, nullable=False)
    roleDescription = Column(Text)
    VocabularyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORROLE {self.ThreatActorRoleID}>'

class THREATACTORSKILLFORATTACKPATTERN(Base):
    __tablename__ = 'THREATACTORSKILLFORATTACKPATTERN'
    __bind_key__  = 'XTHREAT'

    AttackPatternRequiredSkillID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer, nullable=False)
    AttackPatternRequiredSkillOrder = Column(Integer)
    Skill_or_Knowledge_Level = Column(Text)
    SkillLevelID = Column(Integer)
    Skill_or_Knowledge_Type = Column(Text)
    SkillID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORSKILLFORATTACKPATTERN {self.AttackPatternRequiredSkillID}>'

class THREATACTORSOPHISTICATION(Base):
    __tablename__ = 'THREATACTORSOPHISTICATION'
    __bind_key__  = 'XTHREAT'

    ThreatActorSophisticationID = Column(Integer, primary_key=True)
    ThreatActorSophisticationGUID = Column(Text)
    ThreatActorSophisticationName = Column(Text)
    ThreatActorSophisticationDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<THREATACTORSOPHISTICATION {self.ThreatActorSophisticationID}>'

class THREATACTORTACTIC(Base):
    __tablename__ = 'THREATACTORTACTIC'
    __bind_key__  = 'XTHREAT'

    ThreatActorTacticID = Column(Integer, primary_key=True)
    TacticID = Column(Integer)

    def __repr__(self):
        return f'<THREATACTORTACTIC {self.ThreatActorTacticID}>'

class THREATACTORTAG(Base):
    __tablename__ = 'THREATACTORTAG'
    __bind_key__  = 'XTHREAT'

    ThreatActorTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATACTORTAG {self.ThreatActorTagID}>'

class THREATACTORTTP(Base):
    __tablename__ = 'THREATACTORTTP'
    __bind_key__  = 'XTHREAT'

    ThreatActorTTPID = Column(Integer, primary_key=True)
    TTPTitle = Column(Text, nullable=False)
    TTPDescription = Column(Text)
    VocabularyID = Column(Integer)
    Information_Source = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORTTP {self.ThreatActorTTPID}>'

class THREATACTORTTPFORINCIDENT(Base):
    __tablename__ = 'THREATACTORTTPFORINCIDENT'
    __bind_key__  = 'XTHREAT'

    ThreatActorTTPIncidentID = Column(Integer, primary_key=True)
    ThreatActorTTPID = Column(Integer, nullable=False)
    ThreatActorGUID = Column(Text)
    IncidentID = Column(Integer, nullable=False)
    IncidentGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text, nullable=False)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORTTPFORINCIDENT {self.ThreatActorTTPIncidentID}>'

class THREATACTORTTPFORINDICATOR(Base):
    __tablename__ = 'THREATACTORTTPFORINDICATOR'
    __bind_key__  = 'XTHREAT'

    ThreatActorTTPIndicatorID = Column(Integer, primary_key=True)
    ThreatActorTTPID = Column(Integer, nullable=False)
    ThreatActorTTPGUID = Column(Text)
    IndicatorID = Column(Integer, nullable=False)
    IndicatorGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text, nullable=False)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATACTORTTPFORINDICATOR {self.ThreatActorTTPIndicatorID}>'

class THREATACTORTTPFORTHREATACTORTTP(Base):
    __tablename__ = 'THREATACTORTTPFORTHREATACTORTTP'
    __bind_key__  = 'XTHREAT'

    ThreatActorTTPMappingID = Column(Integer, primary_key=True)
    ThreatActorTTPRefID = Column(Integer, nullable=False)
    Relationship = Column(Text)
    ThreatActorTTPSubjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<THREATACTORTTPFORTHREATACTORTTP {self.ThreatActorTTPMappingID}>'

class THREATACTORVARIETY(Base):
    __tablename__ = 'THREATACTORVARIETY'
    __bind_key__  = 'XTHREAT'

    ThreatActorVarietyID = Column(Integer, primary_key=True)
    ThreatActorTypeGUID = Column(Text)
    ExternalVariety = Column(Integer)
    InternalVariety = Column(Integer)
    ActorVariety = Column(Text, nullable=False)
    ActorVarietyDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<THREATACTORVARIETY {self.ThreatActorVarietyID}>'

class THREATAGENT(Base):
    __tablename__ = 'THREATAGENT'
    __bind_key__  = 'XTHREAT'

    ThreatAgentID = Column(Integer, primary_key=True)
    ThreatAgentGUID = Column(Text)
    ThreatAgentName = Column(Text, nullable=False)
    ThreatAgentDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    Capability = Column(Text)
    Intent = Column(Text)
    Targeting = Column(Text)

    def __repr__(self):
        return f'<THREATAGENT {self.ThreatAgentID}>'

class RELATIONSHIP(Base):
    """Relationship between threat objects (aligned with STIX 2.1 Relationship SRO)."""
    __tablename__ = 'RELATIONSHIP'
    __bind_key__  = 'XTHREAT'

    RelationshipID = Column(Integer, primary_key=True)
    RelationshipGUID = Column(Text)        # STIX id "relationship--…"
    relationship_type = Column(Text)        # ex. uses / targets / indicates / mitigates
    source_ref = Column(Text)               # STIX id of the source
    target_ref = Column(Text)               # STIX id of the target
    description = Column(Text)
    start_time = Column(Text)
    stop_time = Column(Text)
    CreatedDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<RELATIONSHIP {self.RelationshipID}>'

class THREATEVENT(Base):
    __tablename__ = 'THREATEVENT'
    __bind_key__  = 'XTHREAT'

    ThreatEventID = Column(Integer, primary_key=True)
    ReferentialID = Column(Text)
    KCPhase = Column(Text)
    Tier = Column(Integer)
    Description = Column(Text)
    VocabularyID = Column(Integer)
    Category = Column(Text)

    def __repr__(self):
        return f'<THREATEVENT {self.ThreatEventID}>'

class THREATAGENTCATEGORY(Base):
    __tablename__ = 'THREATAGENTCATEGORY'
    __bind_key__  = 'XTHREAT'

    ThreatAgentCategoryID = Column(Integer, primary_key=True)
    CategoryID = Column(Integer)
    ThreatAgentID = Column(Integer)

    def __repr__(self):
        return f'<THREATAGENTCATEGORY {self.ThreatAgentCategoryID}>'

class THREATAGENTCHANGERECORD(Base):
    __tablename__ = 'THREATAGENTCHANGERECORD'
    __bind_key__  = 'XTHREAT'

    ThreatAgentChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATAGENTCHANGERECORD {self.ThreatAgentChangeRecordID}>'

class THREATAGENTFOROWASPTOP10(Base):
    __tablename__ = 'THREATAGENTFOROWASPTOP10'
    __bind_key__  = 'XTHREAT'

    OWASPTOP10ThreatAgentID = Column(Integer, primary_key=True)
    OWASPTOP10ID = Column(Integer, nullable=False)
    ThreatAgentID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    LastCheckedDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATAGENTFOROWASPTOP10 {self.OWASPTOP10ThreatAgentID}>'

class THREATAGENTTAG(Base):
    __tablename__ = 'THREATAGENTTAG'
    __bind_key__  = 'XTHREAT'

    ThreatAgentTagID = Column(Integer, primary_key=True)
    ThreatAgentID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATAGENTTAG {self.ThreatAgentTagID}>'

class THREATCAMPAIGN(Base):
    __tablename__ = 'THREATCAMPAIGN'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignID = Column(Integer, primary_key=True)
    ThreatCampaignGUID = Column(Text)
    ThreatCampaignTitle = Column(Text)
    ThreatCampaignStatus = Column(Text)
    ThreatCampaignDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    CollectionMethodID = Column(Integer)
    SourceID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ImportanceID = Column(Integer)

    def __repr__(self):
        return f'<THREATCAMPAIGN {self.ThreatCampaignID}>'

class THREATCAMPAIGNCHANGERECORD(Base):
    __tablename__ = 'THREATCAMPAIGNCHANGERECORD'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATCAMPAIGNCHANGERECORD {self.ThreatCampaignChangeRecordID}>'

class THREATCAMPAIGNDESCRIPTION(Base):
    __tablename__ = 'THREATCAMPAIGNDESCRIPTION'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignDescriptionID = Column(Integer, primary_key=True)
    ThreatCampaignID = Column(Integer, nullable=False)
    ThreatCampaignGUID = Column(Text)
    DescriptionID = Column(Integer, nullable=False)
    DescriptionGUID = Column(Text)
    ConfidentialityLevelID = Column(Integer)
    isEncrypted = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    SourceID = Column(Integer)
    CollectionMethodID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)

    def __repr__(self):
        return f'<THREATCAMPAIGNDESCRIPTION {self.ThreatCampaignDescriptionID}>'

class THREATCAMPAIGNFORTHREATCAMPAIGN(Base):
    __tablename__ = 'THREATCAMPAIGNFORTHREATCAMPAIGN'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignMappingID = Column(Integer, primary_key=True)
    ThreatCampaignRefID = Column(Integer, nullable=False)
    ThreatCampaignRefGUID = Column(Text)
    Relationship = Column(Text)
    ThreatCampaignSubjectID = Column(Integer, nullable=False)
    ThreatCampaignSubjectGUID = Column(Text)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text, nullable=False)
    ConfidenceLevel = Column(Text)
    ConfidenceLevelID = Column(Integer)
    notes = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATCAMPAIGNFORTHREATCAMPAIGN {self.ThreatCampaignMappingID}>'

class THREATCAMPAIGNMETHODOLOGY(Base):
    __tablename__ = 'THREATCAMPAIGNMETHODOLOGY'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignMethodologyID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATCAMPAIGNMETHODOLOGY {self.ThreatCampaignMethodologyID}>'

class THREATCAMPAIGNNAME(Base):
    __tablename__ = 'THREATCAMPAIGNNAME'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignNameID = Column(Integer, primary_key=True)
    ThreatCampaignGUID = Column(Text)
    ThreatCampaignName = Column(Text, nullable=False)
    internalname = Column(Integer)
    externalname = Column(Integer)
    Information_Source = Column(Text)
    CreatedDate = Column(Text, nullable=False)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text, nullable=False)
    ValidFromDate = Column(Text, nullable=False)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATCAMPAIGNNAME {self.ThreatCampaignNameID}>'

class THREATCAMPAIGNNAMEFORTHREATCAMPAIGN(Base):
    __tablename__ = 'THREATCAMPAIGNNAMEFORTHREATCAMPAIGN'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignThreatCampaignNameID = Column(Integer, primary_key=True)
    ThreatCampaignID = Column(Integer, nullable=False)
    ThreatCampaignNameID = Column(Integer, nullable=False)
    CreatedDate = Column(Text, nullable=False)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text, nullable=False)
    ValidFromDate = Column(Text, nullable=False)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<THREATCAMPAIGNNAMEFORTHREATCAMPAIGN {self.ThreatCampaignThreatCampaignNameID}>'

class THREATCAMPAIGNREFERENCE(Base):
    __tablename__ = 'THREATCAMPAIGNREFERENCE'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignReferenceID = Column(Integer, primary_key=True)
    ThreatCampaignID = Column(Integer)
    ThreatCampaignGUID = Column(Text)
    ReferenceID = Column(Integer)
    ReferenceGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<THREATCAMPAIGNREFERENCE {self.ThreatCampaignReferenceID}>'

class THREATCAMPAIGNSOURCE(Base):
    __tablename__ = 'THREATCAMPAIGNSOURCE'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignSourceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATCAMPAIGNSOURCE {self.ThreatCampaignSourceID}>'

class THREATCAMPAIGNSTATUS(Base):
    __tablename__ = 'THREATCAMPAIGNSTATUS'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignStatusID = Column(Integer, primary_key=True)
    CampaignStatus = Column(Text, nullable=False)
    CampaignStatusDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<THREATCAMPAIGNSTATUS {self.ThreatCampaignStatusID}>'

class THREATCAMPAIGNTAG(Base):
    __tablename__ = 'THREATCAMPAIGNTAG'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignTagID = Column(Integer, primary_key=True)
    ThreatCampaignID = Column(Integer, nullable=False)
    ThreatCampaignGUID = Column(Text)
    TagID = Column(Integer, nullable=False)
    TagGUID = Column(Text)
    ConfidentialityLevelID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATCAMPAIGNTAG {self.ThreatCampaignTagID}>'

class THREATCAMPAIGNTECHNIQUE(Base):
    __tablename__ = 'THREATCAMPAIGNTECHNIQUE'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignTechniqueID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATCAMPAIGNTECHNIQUE {self.ThreatCampaignTechniqueID}>'

class THREATCAMPAIGNTOOL(Base):
    __tablename__ = 'THREATCAMPAIGNTOOL'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignToolID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATCAMPAIGNTOOL {self.ThreatCampaignToolID}>'

class THREATCAMPAIGNTYPE(Base):
    __tablename__ = 'THREATCAMPAIGNTYPE'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignTypeID = Column(Integer, primary_key=True)
    CampaignTypeTitle = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<THREATCAMPAIGNTYPE {self.ThreatCampaignTypeID}>'

class THREATCATEGORY(Base):
    __tablename__ = 'THREATCATEGORY'
    __bind_key__  = 'XTHREAT'

    ThreatCategoryID = Column(Integer, primary_key=True)
    ThreatCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    ThreatCategoryName = Column(Text)
    ThreatCategoryDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ImportanceID = Column(Integer)
    ValidityID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATCATEGORY {self.ThreatCategoryID}>'

class THREATCATEGORYDESCRIPTION(Base):
    __tablename__ = 'THREATCATEGORYDESCRIPTION'
    __bind_key__  = 'XTHREAT'

    ThreatCategoryDescriptionID = Column(Integer, primary_key=True)
    ThreatCategoryID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATCATEGORYDESCRIPTION {self.ThreatCategoryDescriptionID}>'

class THREATCATEGORYREFERENCE(Base):
    __tablename__ = 'THREATCATEGORYREFERENCE'
    __bind_key__  = 'XTHREAT'

    ThreatCategoryReferenceID = Column(Integer, primary_key=True)
    ThreatCategoryID = Column(Integer, nullable=False)
    ReferenceID = Column(Integer, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    CreationObjectID = Column(Integer)
    ConfidentialityLevelID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATCATEGORYREFERENCE {self.ThreatCategoryReferenceID}>'

class THREATCATEGORYTAG(Base):
    __tablename__ = 'THREATCATEGORYTAG'
    __bind_key__  = 'XTHREAT'

    ThreatCategoryTagID = Column(Integer, primary_key=True)
    ThreatCategoryID = Column(Integer, nullable=False)
    TagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ValidityID = Column(Integer)
    VocbularyID = Column(Integer)

    def __repr__(self):
        return f'<THREATCATEGORYTAG {self.ThreatCategoryTagID}>'

class THREATINTENDEDEFFECT(Base):
    __tablename__ = 'THREATINTENDEDEFFECT'
    __bind_key__  = 'XTHREAT'

    ThreatIntendedEffectID = Column(Integer, primary_key=True)
    ThreatIntendedEffectGUID = Column(Text)
    IntendedEffectName = Column(Text, nullable=False)
    IntendedEffectDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<THREATINTENDEDEFFECT {self.ThreatIntendedEffectID}>'

class THREATINTENDEDEFFECTFORINCIDENT(Base):
    __tablename__ = 'THREATINTENDEDEFFECTFORINCIDENT'
    __bind_key__  = 'XTHREAT'

    IncidentThreatIntendedEffectID = Column(Integer, primary_key=True)
    ThreatIntendedEffectID = Column(Integer, nullable=False)
    ThreatIntendedEffectGUID = Column(Text)
    IncidentID = Column(Integer, nullable=False)
    IncidentGUID = Column(Text)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text, nullable=False)
    ValidFromDate = Column(Text, nullable=False)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<THREATINTENDEDEFFECTFORINCIDENT {self.IncidentThreatIntendedEffectID}>'

class THREATINTENDEDEFFECTFORTHREATACTORTTP(Base):
    __tablename__ = 'THREATINTENDEDEFFECTFORTHREATACTORTTP'
    __bind_key__  = 'XTHREAT'

    ThreatActorTTPIntendedEffectID = Column(Integer, primary_key=True)
    ThreatIntendedEffectID = Column(Integer, nullable=False)
    ThreatActorTTPID = Column(Integer, nullable=False)
    notes = Column(Text)
    ConfidenceLevel = Column(Text)
    Information_Source = Column(Text)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text, nullable=False)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATINTENDEDEFFECTFORTHREATACTORTTP {self.ThreatActorTTPIntendedEffectID}>'

class THREATINTENDEDEFFECTFORTHREATCAMPAIGN(Base):
    __tablename__ = 'THREATINTENDEDEFFECTFORTHREATCAMPAIGN'
    __bind_key__  = 'XTHREAT'

    ThreatCampaignIntendedEffectID = Column(Integer, primary_key=True)
    ThreatIntendedEffectID = Column(Integer, nullable=False)
    ThreatCampaignID = Column(Integer, nullable=False)
    CreatedDate = Column(Text, nullable=False)
    BLOB = Column(Text, nullable=False)
    ValidFromDate = Column(Text, nullable=False)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<THREATINTENDEDEFFECTFORTHREATCAMPAIGN {self.ThreatCampaignIntendedEffectID}>'

class THREATMOTIVE(Base):
    __tablename__ = 'THREATMOTIVE'
    __bind_key__  = 'XTHREAT'

    ThreatMotiveID = Column(Integer, primary_key=True)
    ThreatMotiveGUID = Column(Text)
    ThreatMotive = Column(Text, nullable=False)        # former "motive" column
    ThreatMotiveDescription = Column(Text)             # former "motiveDescription" column
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntildate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<THREATMOTIVE {self.ThreatMotiveID}>'

class THREATMOTIVEDESCRIPTION(Base):
    __tablename__ = 'THREATMOTIVEDESCRIPTION'
    __bind_key__  = 'XTHREAT'

    ThreatMotiveDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATMOTIVEDESCRIPTION {self.ThreatMotiveDescriptionID}>'

class THREATMOTIVEFORTHREATACTOR(Base):
    __tablename__ = 'THREATMOTIVEFORTHREATACTOR'
    __bind_key__  = 'XTHREAT'

    ThreatActorMotiveID = Column(Integer, primary_key=True)
    ThreatMotiveID = Column(Integer, nullable=False)
    ThreatActorID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATMOTIVEFORTHREATACTOR {self.ThreatActorMotiveID}>'

class THREATMOTIVETAG(Base):
    __tablename__ = 'THREATMOTIVETAG'
    __bind_key__  = 'XTHREAT'

    ThreatMotiveTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<THREATMOTIVETAG {self.ThreatMotiveTagID}>'

class THREATTYPE(Base):
    __tablename__ = 'THREATTYPE'
    __bind_key__  = 'XTHREAT'

    ThreatTypeID = Column(Integer, primary_key=True)
    ThreatTypeGUID = Column(Text)
    ThreatTypeName = Column(Text, nullable=False)
    ThreatTypeDescription = Column(Text)
    VocabularyID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<THREATTYPE {self.ThreatTypeID}>'

class THREATTYPEDESCRIPTION(Base):
    __tablename__ = 'THREATTYPEDESCRIPTION'
    __bind_key__  = 'XTHREAT'

    ThreatTypeDescriptionID = Column(Integer, primary_key=True)
    ThreatTypeID = Column(Integer, nullable=False)
    DescriptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<THREATTYPEDESCRIPTION {self.ThreatTypeDescriptionID}>'
