"""
SQLAlchemy models for XATTACK database
Auto-generated from SQLite schema - replaces XORCISMModel/XATTACK C# POCO classes
"""
from sqlalchemy import Column, Integer, Float, String, Text, LargeBinary, Boolean
from .base import Base


class ATTACKCATEGORY(Base):
    __tablename__ = 'ATTACKCATEGORY'
    __bind_key__  = 'XATTACK'

    AttackCategoryID = Column(Integer, primary_key=True)
    AttackCategoryGUID = Column(Text)
    CategoryID = Column(Integer)
    CategoryGUID = Column(Text)
    AttackCategoryName = Column(Text)
    AttackCategoryDescription = Column(Text)
    VocabularyID = Column(Integer)
    VocabularyGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CreationObjectGUID = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKCATEGORY {self.AttackCategoryID}>'

class ATTACKCATEGORYREFERENCE(Base):
    __tablename__ = 'ATTACKCATEGORYREFERENCE'
    __bind_key__  = 'XATTACK'

    AttackCategoryReferenceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ATTACKCATEGORYREFERENCE {self.AttackCategoryReferenceID}>'

class ATTACKCONSEQUENCE(Base):
    __tablename__ = 'ATTACKCONSEQUENCE'
    __bind_key__  = 'XATTACK'

    AttackConsequenceID = Column(Integer, primary_key=True)
    Consequence = Column(Text)
    ConsequenceNote = Column(Text)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKCONSEQUENCE {self.AttackConsequenceID}>'

class ATTACKCONSEQUENCETAG(Base):
    __tablename__ = 'ATTACKCONSEQUENCETAG'
    __bind_key__  = 'XATTACK'

    AttackConsequenceTagID = Column(Integer, primary_key=True)
    AttackConsequenceID = Column(Integer)
    TagID = Column(Integer)

    def __repr__(self):
        return f'<ATTACKCONSEQUENCETAG {self.AttackConsequenceTagID}>'

class ATTACKEXAMPLE(Base):
    __tablename__ = 'ATTACKEXAMPLE'
    __bind_key__  = 'XATTACK'

    AttackExampleID = Column(Integer, primary_key=True)
    AttackExampleGUID = Column(Text)
    AttackExampleName = Column(Text)
    AttackExampleDescription = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    AttackExampleVocabularyID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKEXAMPLE {self.AttackExampleID}>'

class ATTACKEXAMPLEFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKEXAMPLEFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackExampleForAttackPatternID = Column(Integer, primary_key=True)
    AttackExampleID = Column(Integer, nullable=False)
    AttackExampleGUID = Column(Text)
    AttackPatternID = Column(Integer, nullable=False)
    AttackPatternGUID = Column(Text)
    capec_id = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKEXAMPLEFORATTACKPATTERN {self.AttackExampleForAttackPatternID}>'

class ATTACKEXECUTIONFLOW(Base):
    __tablename__ = 'ATTACKEXECUTIONFLOW'
    __bind_key__  = 'XATTACK'

    AttackExecutionFlowID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    capec_id = Column(Text)
    AttackExecutionFlowGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ATTACKEXECUTIONFLOW {self.AttackExecutionFlowID}>'

class ATTACKEXECUTIONFLOWPHASE(Base):
    __tablename__ = 'ATTACKEXECUTIONFLOWPHASE'
    __bind_key__  = 'XATTACK'

    AttackExecutionFlowPhaseID = Column(Integer, primary_key=True)
    AttackExecutionFlowID = Column(Integer)
    AttackExecutionFlowGUID = Column(Text)
    AttackPhaseID = Column(Integer)
    AttackPhaseGUID = Column(Text)
    AttackPhaseOrder = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKEXECUTIONFLOWPHASE {self.AttackExecutionFlowPhaseID}>'

class ATTACKMETHOD(Base):
    __tablename__ = 'ATTACKMETHOD'
    __bind_key__  = 'XATTACK'

    AttackMethodID = Column(Integer, primary_key=True)
    AttackMethodGUID = Column(Text)
    AttackMethodTitle = Column(Text, nullable=False)
    AttackMethodDescription = Column(Text)
    SourceID = Column(Integer)
    SourceGUID = Column(Text)
    VocabularyID = Column(Integer)
    VocabularyGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CreationObjectGUID = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKMETHOD {self.AttackMethodID}>'

class ATTACKMETHODDESCRIPTION(Base):
    __tablename__ = 'ATTACKMETHODDESCRIPTION'
    __bind_key__  = 'XATTACK'

    AttackMethodDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ATTACKMETHODDESCRIPTION {self.AttackMethodDescriptionID}>'

class ATTACKMETHODFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKMETHODFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternMethodID = Column(Integer, primary_key=True)
    AttackMethodID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKMETHODFORATTACKPATTERN {self.AttackPatternMethodID}>'

class ATTACKMETHODREFERENCE(Base):
    __tablename__ = 'ATTACKMETHODREFERENCE'
    __bind_key__  = 'XATTACK'

    AttackMethodReferenceID = Column(Integer, primary_key=True)
    AttackMethodID = Column(Integer)
    ReferenceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKMETHODREFERENCE {self.AttackMethodReferenceID}>'

class ATTACKMETHODTAG(Base):
    __tablename__ = 'ATTACKMETHODTAG'
    __bind_key__  = 'XATTACK'

    AttackMethodTagID = Column(Integer, primary_key=True)
    AttackMethodID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKMETHODTAG {self.AttackMethodTagID}>'

class ATTACKMOTIVATION(Base):
    __tablename__ = 'ATTACKMOTIVATION'
    __bind_key__  = 'XATTACK'

    AttackMotivationID = Column(Integer, nullable=False, primary_key=True)
    AttackMotivationName = Column(Text)
    AttackMotivationDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ATTACKMOTIVATION {self.AttackMotivationID}>'

class ATTACKPATTERN(Base):
    __tablename__ = 'ATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternID = Column(Integer, primary_key=True)
    AttackPatternGUID = Column(Text)
    capec_id = Column(Text)
    category = Column(Integer)
    AttackPatternName = Column(Text)
    AttackPatternDescription = Column(Text)
    PatternAbstraction = Column(Text)
    PatternCompleteness = Column(Text)
    PatternStatus = Column(Text)
    TypicalSeverity = Column(Text)
    Payload_Activation_Impact = Column(Text)
    SourceID = Column(Integer)
    SourceGUID = Column(Text)
    RepositoryID = Column(Integer)
    RepositoryGUID = Column(Text)
    VocabularyID = Column(Integer)
    VocabularyGUID = Column(Text)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    CreationObjectGUID = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERN {self.AttackPatternID}>'

class ATTACKPATTERNATTACKCONSEQUENCE(Base):
    __tablename__ = 'ATTACKPATTERNATTACKCONSEQUENCE'
    __bind_key__  = 'XATTACK'

    AttackPatternAttackConsequenceID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    AttackPatternGUID = Column(Text)
    CAPECAttackConsequenceOrder = Column(Integer)
    AttackConsequenceID = Column(Integer)
    Consequence_Note = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPATTERNATTACKCONSEQUENCE {self.AttackPatternAttackConsequenceID}>'

class ATTACKPATTERNATTACKCONSEQUENCESCOPE(Base):
    __tablename__ = 'ATTACKPATTERNATTACKCONSEQUENCESCOPE'
    __bind_key__  = 'XATTACK'

    AttackPatternAttackConsequenceScopeID = Column(Integer, primary_key=True)
    AttackPatternAttackConsequenceID = Column(Integer)
    AttackScopeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPATTERNATTACKCONSEQUENCESCOPE {self.AttackPatternAttackConsequenceScopeID}>'

class ATTACKPATTERNATTACKTECHNICALIMPACT(Base):
    __tablename__ = 'ATTACKPATTERNATTACKTECHNICALIMPACT'
    __bind_key__  = 'XATTACK'

    AttackPatternAttackTechnicalImpactID = Column(Integer, primary_key=True)
    AttackPatternAttackConsequenceID = Column(Integer)
    AttackTechnicalImpactID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNATTACKTECHNICALIMPACT {self.AttackPatternAttackTechnicalImpactID}>'

class ATTACKPATTERNCWE(Base):
    __tablename__ = 'ATTACKPATTERNCWE'
    __bind_key__  = 'XATTACK'

    AttackPatternCWEID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    WeaknessRelationship = Column(Text)
    CWEID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNCWE {self.AttackPatternCWEID}>'

class ATTACKPATTERNFORTHREATACTORTTP(Base):
    __tablename__ = 'ATTACKPATTERNFORTHREATACTORTTP'
    __bind_key__  = 'XATTACK'

    AttackPatternForThreatActorTTPID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer, nullable=False)
    ThreatActorTTPID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNFORTHREATACTORTTP {self.AttackPatternForThreatActorTTPID}>'

class ATTACKPATTERNINDICATORWARNING(Base):
    __tablename__ = 'ATTACKPATTERNINDICATORWARNING'
    __bind_key__  = 'XATTACK'

    AttackPatternIndicatorWarningID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    AttackPatternIndicatorWarningOrder = Column(Integer)
    IndicatorWarningAttack = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNINDICATORWARNING {self.AttackPatternIndicatorWarningID}>'

class ATTACKPATTERNMITIGATION(Base):
    __tablename__ = 'ATTACKPATTERNMITIGATION'
    __bind_key__  = 'XATTACK'

    AttackPatternMitigationID = Column(Integer, primary_key=True)
    AttackPatternMitigationGUID = Column(Text)
    AttackPatternID = Column(Integer)
    AttackPatternGUID = Column(Text)
    MitigationID = Column(Integer)
    MitigationGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPATTERNMITIGATION {self.AttackPatternMitigationID}>'

class ATTACKPATTERNNOTE(Base):
    __tablename__ = 'ATTACKPATTERNNOTE'
    __bind_key__  = 'XATTACK'

    AttackPatternNoteID = Column(Integer, primary_key=True)
    NoteText = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNNOTE {self.AttackPatternNoteID}>'

class ATTACKPATTERNNOTES(Base):
    __tablename__ = 'ATTACKPATTERNNOTES'
    __bind_key__  = 'XATTACK'

    AttackPatternNotesID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    NoteOrder = Column(Integer)
    AttackPatternNoteID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNNOTES {self.AttackPatternNotesID}>'

class ATTACKPATTERNOBFUSCATIONTECHNIQUE(Base):
    __tablename__ = 'ATTACKPATTERNOBFUSCATIONTECHNIQUE'
    __bind_key__  = 'XATTACK'

    AttackPatternObfuscationTechniqueID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer, nullable=False)
    AttackPatternGUID = Column(Text)
    ObfuscationTechniqueID = Column(Integer, nullable=False)
    ObfuscationTechniqueGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPATTERNOBFUSCATIONTECHNIQUE {self.AttackPatternObfuscationTechniqueID}>'

class ATTACKPATTERNPROBINGTECHNIQUE(Base):
    __tablename__ = 'ATTACKPATTERNPROBINGTECHNIQUE'
    __bind_key__  = 'XATTACK'

    AttackPatternProbingTechniqueID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    AttackPatternGUID = Column(Text)
    AttackTechniqueID = Column(Integer)
    AttackTechniqueGUID = Column(Text)
    TechniqueID = Column(Integer)
    TechniqueGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPATTERNPROBINGTECHNIQUE {self.AttackPatternProbingTechniqueID}>'

class ATTACKPATTERNREFERENCE(Base):
    __tablename__ = 'ATTACKPATTERNREFERENCE'
    __bind_key__  = 'XATTACK'

    AttackPatternReferenceID = Column(Integer, primary_key=True)
    AttackPatternReferenceGUID = Column(Text)
    AttackPatternID = Column(Integer)
    AttackPatternGUID = Column(Text)
    ReferenceID = Column(Integer)
    ReferenceGUID = Column(Text)
    Reference_ID = Column(Text)
    Local_Reference_ID = Column(Text)
    Reference_Section = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPATTERNREFERENCE {self.AttackPatternReferenceID}>'

class ATTACKPATTERNRELATIONSHIP(Base):
    __tablename__ = 'ATTACKPATTERNRELATIONSHIP'
    __bind_key__  = 'XATTACK'

    AttackPatternRelationshipID = Column(Integer, primary_key=True)
    AttackPatternRefID = Column(Integer)
    AttackPatternRefGUID = Column(Text)
    RelationshipName = Column(Text)
    Relationship_Description = Column(Text)
    AttackPatternSubjectID = Column(Integer)
    AttackPatternSubjectGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNRELATIONSHIP {self.AttackPatternRelationshipID}>'

class ATTACKPATTERNSECURITYCONTROL(Base):
    __tablename__ = 'ATTACKPATTERNSECURITYCONTROL'
    __bind_key__  = 'XATTACK'

    AttackPatternSecurityControlID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    SecurityControlID = Column(Integer)
    AttackPatternSecurityControlVocabularyID = Column(Integer)
    AttackPatternSecurityControlOrder = Column(Integer)
    SecurityControlTypeID = Column(Integer)
    SecurityControlType = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ATTACKPATTERNSECURITYCONTROL {self.AttackPatternSecurityControlID}>'

class ATTACKPATTERNTAG(Base):
    __tablename__ = 'ATTACKPATTERNTAG'
    __bind_key__  = 'XATTACK'

    AttackPatternTagID = Column(Integer, primary_key=True)
    AttackPatternTagGUID = Column(Text)
    AttackPatternID = Column(Integer)
    AttackPatternGUID = Column(Text)
    TagID = Column(Integer)
    TagGUID = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNTAG {self.AttackPatternTagID}>'

class ATTACKPATTERNVIEW(Base):
    __tablename__ = 'ATTACKPATTERNVIEW'
    __bind_key__  = 'XATTACK'

    AttackPatternViewID = Column(Integer, primary_key=True)
    AttackPatternViewGUID = Column(Text)
    ViewVocabularyID = Column(Integer)
    AttackPatternViewName = Column(Text)
    View_Structure = Column(Text)
    AttackPatternViewDescription = Column(Text)
    View_Filter = Column(Text)
    ViewStatus = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNVIEW {self.AttackPatternViewID}>'

class ATTACKPATTERNVIEWRELATIONSHIP(Base):
    __tablename__ = 'ATTACKPATTERNVIEWRELATIONSHIP'
    __bind_key__  = 'XATTACK'

    AttackPatternViewRelationshipID = Column(Integer, primary_key=True)
    AttackPatternViewID = Column(Integer)
    Ordinal = Column(Text)
    Relationship_Target_Form = Column(Text)
    Relationship_Nature = Column(Text)
    Relationship_Description = Column(Text)
    AttackPatternID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPATTERNVIEWRELATIONSHIP {self.AttackPatternViewRelationshipID}>'

class ATTACKPAYLOAD(Base):
    __tablename__ = 'ATTACKPAYLOAD'
    __bind_key__  = 'XATTACK'

    AttackPayloadID = Column(Integer, primary_key=True)
    AttackPayloadGUID = Column(Text)
    PayloadText = Column(Text, nullable=False)
    Payload_Activation_Impact = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromdate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPAYLOAD {self.AttackPayloadID}>'

class ATTACKPAYLOADENCODER(Base):
    __tablename__ = 'ATTACKPAYLOADENCODER'
    __bind_key__  = 'XATTACK'

    AttackPayloadEncoderID = Column(Integer, primary_key=True)
    AttackPayloadEncoderName = Column(Text)
    AttackPayloadEncoderDescription = Column(Text)
    AttackPayloadEncoderVersion = Column(Text)
    BLOB = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPAYLOADENCODER {self.AttackPayloadEncoderID}>'

class ATTACKPAYLOADFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKPAYLOADFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternPayloadID = Column(Integer, primary_key=True)
    AttackPatternPayloadGUID = Column(Text)
    AttackPayloadID = Column(Integer, nullable=False)
    AttackPayloadGUID = Column(Text)
    AttackPayloadImpactID = Column(Integer)
    AttackPatternID = Column(Integer, nullable=False)
    AttackPatternGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPAYLOADFORATTACKPATTERN {self.AttackPatternPayloadID}>'

class ATTACKPAYLOADIMPACT(Base):
    __tablename__ = 'ATTACKPAYLOADIMPACT'
    __bind_key__  = 'XATTACK'

    AttackPayloadImpactID = Column(Integer, primary_key=True)
    PayloadActivationImpactDescription = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPAYLOADIMPACT {self.AttackPayloadImpactID}>'

class ATTACKPAYLOADIMPACTFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKPAYLOADIMPACTFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternPayloadImpactID = Column(Integer, primary_key=True)
    AttackPayloadImpactID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer, nullable=False)
    capec_id = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPAYLOADIMPACTFORATTACKPATTERN {self.AttackPatternPayloadImpactID}>'

class ATTACKPHASE(Base):
    __tablename__ = 'ATTACKPHASE'
    __bind_key__  = 'XATTACK'

    AttackPhaseID = Column(Integer, primary_key=True)
    AttackPhaseGUID = Column(Text)
    PhaseID = Column(Integer)
    AttackPhaseName = Column(Text)
    AttackPhaseDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPHASE {self.AttackPhaseID}>'

class ATTACKPHASEFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKPHASEFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternAttackPhaseID = Column(Integer, primary_key=True)
    AttackPatternID = Column(Integer)
    AttackPatternGUID = Column(Text)
    AttackPhaseGUID = Column(Text)
    AttackPhaseID = Column(Integer)
    AttackPhaseVocabularyID = Column(Integer)
    AttackPhaseOrder = Column(Integer)
    AttackPhaseDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPHASEFORATTACKPATTERN {self.AttackPatternAttackPhaseID}>'

class ATTACKPREREQUISITE(Base):
    __tablename__ = 'ATTACKPREREQUISITE'
    __bind_key__  = 'XATTACK'

    AttackPrerequisiteID = Column(Integer, primary_key=True)
    AttackPrerequisiteGUID = Column(Text)
    PrerequisiteText = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKPREREQUISITE {self.AttackPrerequisiteID}>'

class ATTACKPREREQUISITEFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKPREREQUISITEFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternAttackPrerequisiteID = Column(Integer, primary_key=True)
    AttackPrerequisiteID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPREREQUISITEFORATTACKPATTERN {self.AttackPatternAttackPrerequisiteID}>'

class ATTACKPURPOSE(Base):
    __tablename__ = 'ATTACKPURPOSE'
    __bind_key__  = 'XATTACK'

    AttackPurposeID = Column(Integer, primary_key=True)
    AttackPurposeGUID = Column(Text)
    AttackPurposeName = Column(Text, nullable=False)
    AttackPurposeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPURPOSE {self.AttackPurposeID}>'

class ATTACKPURPOSEFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKPURPOSEFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternPurposeID = Column(Integer, primary_key=True)
    AttackPurposeID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKPURPOSEFORATTACKPATTERN {self.AttackPatternPurposeID}>'

class ATTACKRESOURCE(Base):
    __tablename__ = 'ATTACKRESOURCE'
    __bind_key__  = 'XATTACK'

    AttackResourceID = Column(Integer, primary_key=True)
    AttackResourceText = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKRESOURCE {self.AttackResourceID}>'

class ATTACKRESOURCEFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKRESOURCEFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternAttackResourceRequiredID = Column(Integer, primary_key=True)
    AttackResourceID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKRESOURCEFORATTACKPATTERN {self.AttackPatternAttackResourceRequiredID}>'

class ATTACKRESOURCELEVEL(Base):
    __tablename__ = 'ATTACKRESOURCELEVEL'
    __bind_key__  = 'XATTACK'

    AttackResourceLevelID = Column(Integer, nullable=False, primary_key=True)
    AttackResourceLevelName = Column(Text)
    AttackResourceLevelDescription = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ATTACKRESOURCELEVEL {self.AttackResourceLevelID}>'

class ATTACKRESOURCETAG(Base):
    __tablename__ = 'ATTACKRESOURCETAG'
    __bind_key__  = 'XATTACK'

    AttackResourceTagID = Column(Integer, primary_key=True)
    AttackResourceID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKRESOURCETAG {self.AttackResourceTagID}>'

class ATTACKSCENARIO(Base):
    __tablename__ = 'ATTACKSCENARIO'
    __bind_key__  = 'XATTACK'

    AttackScenarioID = Column(Integer, primary_key=True)
    ScenarioID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ATTACKSCENARIO {self.AttackScenarioID}>'

class ATTACKSCOPE(Base):
    __tablename__ = 'ATTACKSCOPE'
    __bind_key__  = 'XATTACK'

    AttackScopeID = Column(Integer, primary_key=True)
    AttackScopeGUID = Column(Text)
    ConsequenceScope = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSCOPE {self.AttackScopeID}>'

class ATTACKSTEP(Base):
    __tablename__ = 'ATTACKSTEP'
    __bind_key__  = 'XATTACK'

    AttackStepID = Column(Integer, primary_key=True)
    AttackStepGUID = Column(Text)
    AttackPatternAttackPhaseID = Column(Integer)
    AttackStepVocabularyID = Column(Integer)
    AttackStepOrder = Column(Integer)
    Attack_Step_Title = Column(Text)
    Attack_Step_Description = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSTEP {self.AttackStepID}>'

class ATTACKSTEPINDICATOR(Base):
    __tablename__ = 'ATTACKSTEPINDICATOR'
    __bind_key__  = 'XATTACK'

    AttackStepIndicatorID = Column(Integer, primary_key=True)
    AttackStepIndicatorGUID = Column(Text)
    AttackStepID = Column(Integer)
    AttackStepGUID = Column(Text)
    IndicatorID = Column(Integer)
    IndicatorGUID = Column(Text)
    AttackStepIndicatorVocabularyID = Column(Text)
    AttackStepIndicatorType = Column(Text)
    AttackStepIndicatorDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSTEPINDICATOR {self.AttackStepIndicatorID}>'

class ATTACKSTEPINDICATORENVIRONMENT(Base):
    __tablename__ = 'ATTACKSTEPINDICATORENVIRONMENT'
    __bind_key__  = 'XATTACK'

    AttackStepIndicatorEnvironmentID = Column(Integer, primary_key=True)
    AttackStepIndicatorID = Column(Integer, nullable=False)
    EnvironmentID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSTEPINDICATORENVIRONMENT {self.AttackStepIndicatorEnvironmentID}>'

class ATTACKSTEPINDICATORTAG(Base):
    __tablename__ = 'ATTACKSTEPINDICATORTAG'
    __bind_key__  = 'XATTACK'

    AttackStepIndicatorTagID = Column(Integer, primary_key=True)
    AttackStepIndicatorID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSTEPINDICATORTAG {self.AttackStepIndicatorTagID}>'

class ATTACKSTEPOUTCOME(Base):
    __tablename__ = 'ATTACKSTEPOUTCOME'
    __bind_key__  = 'XATTACK'

    AttackStepOutcomeID = Column(Integer, primary_key=True)
    AttackStepID = Column(Integer)
    OutcomeVocabularyID = Column(Text)
    OutcomeType = Column(Text)
    OutcomeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSTEPOUTCOME {self.AttackStepOutcomeID}>'

class ATTACKSTEPOUTCOMETAG(Base):
    __tablename__ = 'ATTACKSTEPOUTCOMETAG'
    __bind_key__  = 'XATTACK'

    AttackStepOutcomeTagID = Column(Integer, primary_key=True)
    AttackStepOutcomeID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSTEPOUTCOMETAG {self.AttackStepOutcomeTagID}>'

class ATTACKSTEPSECURITYCONTROL(Base):
    __tablename__ = 'ATTACKSTEPSECURITYCONTROL'
    __bind_key__  = 'XATTACK'

    AttackStepSecurityControlID = Column(Integer, primary_key=True)
    AttackStepID = Column(Integer)
    AttackStepGUID = Column(Text)
    SecurityControlID = Column(Integer)
    SecurityControlGUID = Column(Text)
    AttackStepSecurityControlVocabularyID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSTEPSECURITYCONTROL {self.AttackStepSecurityControlID}>'

class ATTACKSTEPTAG(Base):
    __tablename__ = 'ATTACKSTEPTAG'
    __bind_key__  = 'XATTACK'

    AttackStepTagID = Column(Integer, primary_key=True)
    AttackStepID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSTEPTAG {self.AttackStepTagID}>'

class ATTACKSTEPTECHNIQUE(Base):
    __tablename__ = 'ATTACKSTEPTECHNIQUE'
    __bind_key__  = 'XATTACK'

    AttackStepTechniqueID = Column(Integer, primary_key=True)
    AttackStepTechniqueGUID = Column(Text)
    AttackStepTechniqueVocabularyID = Column(Text)
    AttackStepID = Column(Integer)
    AttackTechniqueID = Column(Integer)
    AttackStepTechniqueOrder = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSTEPTECHNIQUE {self.AttackStepTechniqueID}>'

class ATTACKSTEPTECHNIQUEENVIRONMENT(Base):
    __tablename__ = 'ATTACKSTEPTECHNIQUEENVIRONMENT'
    __bind_key__  = 'XATTACK'

    AttackStepTechniqueEnvironmentID = Column(Integer, primary_key=True)
    AttackStepTechniqueID = Column(Integer)
    EnvironmentID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSTEPTECHNIQUEENVIRONMENT {self.AttackStepTechniqueEnvironmentID}>'

class ATTACKSTEPTECHNIQUELEVERAGEDPATTERN(Base):
    __tablename__ = 'ATTACKSTEPTECHNIQUELEVERAGEDPATTERN'
    __bind_key__  = 'XATTACK'

    AttackStepTechniqueLeveragedPatternID = Column(Integer, primary_key=True)
    AttackStepTechniqueID = Column(Integer)
    AttackStepTechniqueGUID = Column(Text)
    AttackPatternID = Column(Integer)
    AttackPatternGUID = Column(Text)
    LeveragedAttackPatternOrder = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSTEPTECHNIQUELEVERAGEDPATTERN {self.AttackStepTechniqueLeveragedPatternID}>'

class ATTACKSURFACE(Base):
    __tablename__ = 'ATTACKSURFACE'
    __bind_key__  = 'XATTACK'

    AttackSurfaceID = Column(Integer, primary_key=True)
    AttackSurfaceGUID = Column(Text)
    AttackSurfaceName = Column(Text)
    AttackSurfaceDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    ConfidenceReasonID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSURFACE {self.AttackSurfaceID}>'

class ATTACKSURFACECHANGERECORD(Base):
    __tablename__ = 'ATTACKSURFACECHANGERECORD'
    __bind_key__  = 'XATTACK'

    AttackSurfaceChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ATTACKSURFACECHANGERECORD {self.AttackSurfaceChangeRecordID}>'

class ATTACKSURFACEFORATTACKPATTERN(Base):
    __tablename__ = 'ATTACKSURFACEFORATTACKPATTERN'
    __bind_key__  = 'XATTACK'

    AttackPatternSurfaceID = Column(Integer, primary_key=True)
    AttackSurfaceID = Column(Integer, nullable=False)
    AttackPatternID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSURFACEFORATTACKPATTERN {self.AttackPatternSurfaceID}>'

class ATTACKSURFACEINTERACTIONPOINTS(Base):
    __tablename__ = 'ATTACKSURFACEINTERACTIONPOINTS'
    __bind_key__  = 'XATTACK'

    AttackSurfaceInteractionPointsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ATTACKSURFACEINTERACTIONPOINTS {self.AttackSurfaceInteractionPointsID}>'

class ATTACKSURFACELOCALITY(Base):
    __tablename__ = 'ATTACKSURFACELOCALITY'
    __bind_key__  = 'XATTACK'

    AttackSurfaceLocalityID = Column(Integer, primary_key=True)
    AttackSurfaceLocalityName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSURFACELOCALITY {self.AttackSurfaceLocalityID}>'

class ATTACKSURFACELOCALITYFORATTACKSURFACE(Base):
    __tablename__ = 'ATTACKSURFACELOCALITYFORATTACKSURFACE'
    __bind_key__  = 'XATTACK'

    AttackSurfaceLocalitiesID = Column(Integer, primary_key=True)
    AttackSurfaceLocalityID = Column(Integer, nullable=False)
    AttackSurfaceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSURFACELOCALITYFORATTACKSURFACE {self.AttackSurfaceLocalitiesID}>'

class ATTACKSURFACESERVICE(Base):
    __tablename__ = 'ATTACKSURFACESERVICE'
    __bind_key__  = 'XATTACK'

    AttackSurfaceServiceID = Column(Integer, primary_key=True)
    AttackSurfaceID = Column(Integer, nullable=False)
    EndPointID = Column(Integer)
    TargetFunctionalServiceID = Column(Integer)
    TargetFunctionalServiceName = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSURFACESERVICE {self.AttackSurfaceServiceID}>'

class ATTACKSURFACESERVICEPROTOCOL(Base):
    __tablename__ = 'ATTACKSURFACESERVICEPROTOCOL'
    __bind_key__  = 'XATTACK'

    AttackSurfaceServiceProtocolID = Column(Integer, primary_key=True)
    AttackSurfaceServiceID = Column(Integer, nullable=False)
    TargetFunctionalServiceProtocolID = Column(Integer)
    ProtocolID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSURFACESERVICEPROTOCOL {self.AttackSurfaceServiceProtocolID}>'

class ATTACKSURFACETYPE(Base):
    __tablename__ = 'ATTACKSURFACETYPE'
    __bind_key__  = 'XATTACK'

    AttackSurfaceTypeID = Column(Integer, primary_key=True)
    AttackSurfaceTypeName = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKSURFACETYPE {self.AttackSurfaceTypeID}>'

class ATTACKSURFACETYPEFORATTACKSURFACE(Base):
    __tablename__ = 'ATTACKSURFACETYPEFORATTACKSURFACE'
    __bind_key__  = 'XATTACK'

    AttackSurfaceTypesID = Column(Integer, primary_key=True)
    AttackSurfaceTypeID = Column(Integer, nullable=False)
    AttackSurfaceID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<ATTACKSURFACETYPEFORATTACKSURFACE {self.AttackSurfaceTypesID}>'

class ATTACKTECHNICALIMPACT(Base):
    __tablename__ = 'ATTACKTECHNICALIMPACT'
    __bind_key__  = 'XATTACK'

    AttackTechnicalImpactID = Column(Integer, primary_key=True)
    AttackTechnicalImpactGUID = Column(Text)
    ImpactID = Column(Integer)
    ConsequenceTechnicalImpact = Column(Text, nullable=False)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKTECHNICALIMPACT {self.AttackTechnicalImpactID}>'

class ATTACKTECHNIQUE(Base):
    __tablename__ = 'ATTACKTECHNIQUE'
    __bind_key__  = 'XATTACK'

    AttackTechniqueID = Column(Integer, primary_key=True)
    AttackTechniqueGUID = Column(Text)
    TechniqueID = Column(Integer)
    AttackTechniqueName = Column(Text)
    AttackTechniqueDescription = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKTECHNIQUE {self.AttackTechniqueID}>'

class ATTACKTECHNIQUEINDICATOR(Base):
    __tablename__ = 'ATTACKTECHNIQUEINDICATOR'
    __bind_key__  = 'XATTACK'

    AttackTechniqueIndicatorID = Column(Integer, primary_key=True)
    AttackTechniqueID = Column(Integer)
    IndicatorID = Column(Integer)
    CreatedDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKTECHNIQUEINDICATOR {self.AttackTechniqueIndicatorID}>'

class ATTACKTECHNIQUEREFERENCE(Base):
    __tablename__ = 'ATTACKTECHNIQUEREFERENCE'
    __bind_key__  = 'XATTACK'

    AttackTechniqueReferenceID = Column(Integer, primary_key=True)
    AttackTechniqueID = Column(Integer)
    ReferenceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKTECHNIQUEREFERENCE {self.AttackTechniqueReferenceID}>'

class ATTACKTECHNIQUETAG(Base):
    __tablename__ = 'ATTACKTECHNIQUETAG'
    __bind_key__  = 'XATTACK'

    AttackTechniqueTagID = Column(Integer, primary_key=True)
    AttackTechniqueID = Column(Integer)
    AttackTechniqueGUID = Column(Text)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKTECHNIQUETAG {self.AttackTechniqueTagID}>'

class ATTACKTECHNIQUETOOL(Base):
    __tablename__ = 'ATTACKTECHNIQUETOOL'
    __bind_key__  = 'XATTACK'

    AttackTechniqueToolID = Column(Integer, primary_key=True)
    AttackTechniqueID = Column(Integer)
    AttackTechniqueGUID = Column(Text)
    AttackToolID = Column(Integer)
    AttackToolGUID = Column(Text)
    ToolID = Column(Integer)
    ToolGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKTECHNIQUETOOL {self.AttackTechniqueToolID}>'

class ATTACKTOOL(Base):
    __tablename__ = 'ATTACKTOOL'
    __bind_key__  = 'XATTACK'

    AttackToolID = Column(Integer, primary_key=True)
    AttackTooldGUID = Column(Text)
    TooldID = Column(Integer)
    AttackToolTypeID = Column(Integer)
    AttackToolName = Column(Text, nullable=False)
    AttackToolVersion = Column(Text)
    VersionID = Column(Integer)
    AttackToolDescription = Column(Text)
    AttackToolAuthor = Column(Text)
    AttackToolLink = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKTOOL {self.AttackToolID}>'

class ATTACKTOOLAUTHENTICATIONTYPE(Base):
    __tablename__ = 'ATTACKTOOLAUTHENTICATIONTYPE'
    __bind_key__  = 'XATTACK'

    AttackToolAuthenticationTypeID = Column(Integer, primary_key=True)
    AttackToolID = Column(Integer)
    AuthenticationTypeID = Column(Integer)
    AttackToolAuthenticationTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKTOOLAUTHENTICATIONTYPE {self.AttackToolAuthenticationTypeID}>'

class ATTACKTOOLDESCRIPTION(Base):
    __tablename__ = 'ATTACKTOOLDESCRIPTION'
    __bind_key__  = 'XATTACK'

    AttackToolDescriptionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ATTACKTOOLDESCRIPTION {self.AttackToolDescriptionID}>'

class ATTACKTOOLFORTHREATACTORTTP(Base):
    __tablename__ = 'ATTACKTOOLFORTHREATACTORTTP'
    __bind_key__  = 'XATTACK'

    ThreatActorTTPAttackToolID = Column(Integer, primary_key=True)
    AttackToolID = Column(Integer, nullable=False)
    ThreatActorTTPID = Column(Integer, nullable=False)
    notes = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<ATTACKTOOLFORTHREATACTORTTP {self.ThreatActorTTPAttackToolID}>'

class ATTACKTOOLMODULE(Base):
    __tablename__ = 'ATTACKTOOLMODULE'
    __bind_key__  = 'XATTACK'

    AttackToolModuleID = Column(Integer, primary_key=True)
    AttackToolModuleName = Column(Text)
    AttackToolModuleDescription = Column(Text)
    AttackToolModuleVersion = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKTOOLMODULE {self.AttackToolModuleID}>'

class ATTACKTOOLMODULEAUTHENTICATIONTYPE(Base):
    __tablename__ = 'ATTACKTOOLMODULEAUTHENTICATIONTYPE'
    __bind_key__  = 'XATTACK'

    AttackToolModuleAuthenticationTypeID = Column(Integer, primary_key=True)
    AttackToolModuleID = Column(Integer)
    AuthenticationTypeID = Column(Integer)
    AttackToolModuleAuthenticationTypeDescription = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CreatedDate = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<ATTACKTOOLMODULEAUTHENTICATIONTYPE {self.AttackToolModuleAuthenticationTypeID}>'

class ATTACKTOOLTAG(Base):
    __tablename__ = 'ATTACKTOOLTAG'
    __bind_key__  = 'XATTACK'

    AttackToolTagID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<ATTACKTOOLTAG {self.AttackToolTagID}>'

class ATTACKTOOLTYPE(Base):
    __tablename__ = 'ATTACKTOOLTYPE'
    __bind_key__  = 'XATTACK'

    AttackToolTypeID = Column(Integer, primary_key=True)
    AttackToolTypeGUID = Column(Text)
    AttackToolTypeName = Column(Text, nullable=False)
    AttackToolTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    EnumerationVersionID = Column(Integer)

    def __repr__(self):
        return f'<ATTACKTOOLTYPE {self.AttackToolTypeID}>'

class ATTACKVECTOR(Base):
    __tablename__ = 'ATTACKVECTOR'
    __bind_key__  = 'XATTACK'

    AttackVectorID = Column(Integer, primary_key=True)
    AttackVectorName = Column(Text)
    AttackvectorDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<ATTACKVECTOR {self.AttackVectorID}>'
