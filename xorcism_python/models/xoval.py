"""
SQLAlchemy models for XOVAL database
Auto-generated from SQLite schema - replaces XORCISMModel/XOVAL C# POCO classes
"""
from sqlalchemy import Column, Integer, Float, String, Text, LargeBinary, Boolean
from .base import Base


class OPERATORENUMERATION(Base):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'OPERATORENUMERATION'
    __bind_key__  = 'XOVAL'

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

class OVALBEHAVIOR(Base):
    __tablename__ = 'OVALBEHAVIOR'
    __bind_key__  = 'XOVAL'

    OVALBehaviorID = Column(Integer, primary_key=True)
    BehaviorKey = Column(Text)
    BehaviorValue = Column(Text)
    BehaviorID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALBEHAVIOR {self.OVALBehaviorID}>'

class OVALBEHAVIORFOROVALOBJECT(Base):
    __tablename__ = 'OVALBEHAVIORFOROVALOBJECT'
    __bind_key__  = 'XOVAL'

    OVALObjectBehaviorID = Column(Integer, primary_key=True)
    OVALObjectID = Column(Integer, nullable=False)
    OVALBehaviorID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<OVALBEHAVIORFOROVALOBJECT {self.OVALObjectBehaviorID}>'

class OVALCLASSDIRECTIVES(Base):
    __tablename__ = 'OVALCLASSDIRECTIVES'
    __bind_key__  = 'XOVAL'

    OVALClassDirectivesID = Column(Integer, primary_key=True)
    OVALClassEnumerationID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALCLASSDIRECTIVES {self.OVALClassDirectivesID}>'

class OVALCLASSDIRECTIVESFOROVALDIRECTIVES(Base):
    __tablename__ = 'OVALCLASSDIRECTIVESFOROVALDIRECTIVES'
    __bind_key__  = 'XOVAL'

    OVALDirectivesID = Column(Integer, primary_key=True)
    OVALClassDirectivesID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALCLASSDIRECTIVESFOROVALDIRECTIVES {self.OVALDirectivesID}>'

class OVALCLASSDIRECTIVESFOROVALRESULTS(Base):
    __tablename__ = 'OVALCLASSDIRECTIVESFOROVALRESULTS'
    __bind_key__  = 'XOVAL'

    OVALResultsID = Column(Integer, primary_key=True)
    OVALClassDirectivesID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALCLASSDIRECTIVESFOROVALRESULTS {self.OVALResultsID}>'

class OVALCLASSENUMERATION(Base):
    __tablename__ = 'OVALCLASSENUMERATION'
    __bind_key__  = 'XOVAL'

    OVALClassEnumerationID = Column(Integer, primary_key=True)
    OVALClassEnumerationGUID = Column(Text)
    ClassValue = Column(Text, nullable=False)
    ClassDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALCLASSENUMERATION {self.OVALClassEnumerationID}>'

class OVALCOMPONENTGROUP(Base):
    __tablename__ = 'OVALCOMPONENTGROUP'
    __bind_key__  = 'XOVAL'

    OVALComponentGroupID = Column(Integer, primary_key=True)
    OVALVariableID = Column(Integer)
    OVALFunctionID = Column(Integer)
    FunctionName = Column(Text)
    FunctionOperation = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OVALCOMPONENTGROUP {self.OVALComponentGroupID}>'

class OVALCRITERIA(Base):
    __tablename__ = 'OVALCRITERIA'
    __bind_key__  = 'XOVAL'

    OVALCriteriaID = Column(Integer, primary_key=True)
    OperatorEnumerationID = Column(Integer)
    negate = Column(Integer)
    comment = Column(Text)
    applicabilitycheck = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALCRITERIA {self.OVALCriteriaID}>'

class OVALCRITERIACRITERION(Base):
    __tablename__ = 'OVALCRITERIACRITERION'
    __bind_key__  = 'XOVAL'

    OVALCriteriaCriterionID = Column(Integer, primary_key=True)
    OVALCriteriaID = Column(Integer, nullable=False)
    negate = Column(Integer)
    OVALTestID = Column(Integer)
    comment = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OVALCRITERIACRITERION {self.OVALCriteriaCriterionID}>'

class OVALCRITERIAEXTENDDEFINITION(Base):
    __tablename__ = 'OVALCRITERIAEXTENDDEFINITION'
    __bind_key__  = 'XOVAL'

    OVALCriteriaExtendDefinitionID = Column(Integer, primary_key=True)
    OVALCriteriaID = Column(Integer, nullable=False)
    negate = Column(Integer)
    OVALDefinitionID = Column(Integer)
    comment = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALCRITERIAEXTENDDEFINITION {self.OVALCriteriaExtendDefinitionID}>'

class OVALCRITERIAFOROVALCRITERIA(Base):
    __tablename__ = 'OVALCRITERIAFOROVALCRITERIA'
    __bind_key__  = 'XOVAL'

    OVALCriteriaRelationshipID = Column(Integer, primary_key=True)
    OVALCriteriaRefID = Column(Integer, nullable=False)
    RelationshipName = Column(Text)
    OVALCriteriaSubjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CriteriaRank = Column(Integer)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OVALCRITERIAFOROVALCRITERIA {self.OVALCriteriaRelationshipID}>'

class OVALCRITERIATYPE(Base):
    __tablename__ = 'OVALCRITERIATYPE'
    __bind_key__  = 'XOVAL'

    OVALCriteriaTypeID = Column(Integer, primary_key=True)
    OperatorEnumerationID = Column(Integer, nullable=False)
    OperatorValue = Column(Text, nullable=False)
    negate = Column(Integer)
    ResultEnumerationID = Column(Integer, nullable=False)
    applicability_check = Column(Integer)

    def __repr__(self):
        return f'<OVALCRITERIATYPE {self.OVALCriteriaTypeID}>'

class OVALCRITERIATYPEFOROVALDEFINITIONTYPE(Base):
    __tablename__ = 'OVALCRITERIATYPEFOROVALDEFINITIONTYPE'
    __bind_key__  = 'XOVAL'

    OVALDefinitionTypeID = Column(Integer, primary_key=True)
    OVALCriteriaTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALCRITERIATYPEFOROVALDEFINITIONTYPE {self.OVALDefinitionTypeID}>'

class OVALCRITERION(Base):
    __tablename__ = 'OVALCRITERION'
    __bind_key__  = 'XOVAL'

    OVALCriterionID = Column(Integer, primary_key=True)
    OVALTestIDPattern = Column(Text, nullable=False)
    negate = Column(Integer)
    comment = Column(Text)
    applicabilitycheck = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALCRITERION {self.OVALCriterionID}>'

class OVALCRITERIONTYPE(Base):
    __tablename__ = 'OVALCRITERIONTYPE'
    __bind_key__  = 'XOVAL'

    OVALCriterionTypeID = Column(Integer, primary_key=True)
    OVALTestID = Column(Integer)
    OVALTestIDPattern = Column(Text, nullable=False)
    OVALTestVersion = Column(Integer, nullable=False)
    variable_instance = Column(Integer)
    negate = Column(Integer)
    ResultEnumerationID = Column(Integer, nullable=False)
    applicability_check = Column(Integer)

    def __repr__(self):
        return f'<OVALCRITERIONTYPE {self.OVALCriterionTypeID}>'

class OVALCRITERIONTYPEFOROVALCRITERIATYPE(Base):
    __tablename__ = 'OVALCRITERIONTYPEFOROVALCRITERIATYPE'
    __bind_key__  = 'XOVAL'

    OVALCriteriaTypeID = Column(Integer, primary_key=True)
    OVALCriterionTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALCRITERIONTYPEFOROVALCRITERIATYPE {self.OVALCriteriaTypeID}>'

class OVALDEFAULTDIRECTIVES(Base):
    __tablename__ = 'OVALDEFAULTDIRECTIVES'
    __bind_key__  = 'XOVAL'

    OVALDefaultDirectivesID = Column(Integer, primary_key=True)
    include_source_definitions = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFAULTDIRECTIVES {self.OVALDefaultDirectivesID}>'

class OVALDEFINITION(Base):
    __tablename__ = 'OVALDEFINITION'
    __bind_key__  = 'XOVAL'

    OVALDefinitionID = Column(Integer, primary_key=True)
    OVALDefinitionIDPattern = Column(Text, nullable=False)
    OVALDefinitionVersion = Column(Integer, nullable=False)
    OVALClassEnumerationID = Column(Integer)
    deprecated = Column(Integer)
    OVALDefinitionTitle = Column(Text)
    OVALDefinitionDescription = Column(Text)
    notes = Column(Text)
    OVALCriteriaID = Column(Integer)
    signature = Column(Text)
    StatusName = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITION {self.OVALDefinitionID}>'

class OVALDEFINITIONCCE(Base):
    __tablename__ = 'OVALDEFINITIONCCE'
    __bind_key__  = 'XOVAL'

    OVALDefinitionCCEID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer, nullable=False)
    CCEID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONCCE {self.OVALDefinitionCCEID}>'

class OVALDEFINITIONCHANGE(Base):
    __tablename__ = 'OVALDEFINITIONCHANGE'
    __bind_key__  = 'XOVAL'

    OVALDefinitionChangeID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ChangeDate = Column(Text)
    ChangeTypeName = Column(Text)
    ChangeValue = Column(Text)
    ChangeComment = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONCHANGE {self.OVALDefinitionChangeID}>'

class OVALDEFINITIONCHANGES(Base):
    __tablename__ = 'OVALDEFINITIONCHANGES'
    __bind_key__  = 'XOVAL'

    OVALDefinitionChangesID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    OVALDefinitionChangeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    OrganisationID = Column(Integer)
    PersonID = Column(Integer)
    AuthorID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONCHANGES {self.OVALDefinitionChangesID}>'

class OVALDEFINITIONCPE(Base):
    __tablename__ = 'OVALDEFINITIONCPE'
    __bind_key__  = 'XOVAL'

    OVALDefinitionCPEID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    OVALDefinitionCPERelationship = Column(Text)
    CPEID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONCPE {self.OVALDefinitionCPEID}>'

class OVALDEFINITIONFAMILY(Base):
    __tablename__ = 'OVALDEFINITIONFAMILY'
    __bind_key__  = 'XOVAL'

    OVALDefinitionFamilyID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    OSFamilyID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONFAMILY {self.OVALDefinitionFamilyID}>'

class OVALDEFINITIONORGANISATION(Base):
    __tablename__ = 'OVALDEFINITIONORGANISATION'
    __bind_key__  = 'XOVAL'

    OrganisationOVALDefinitionID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer, nullable=False)
    OrganisationID = Column(Integer, nullable=False)
    OrganisationRole = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONORGANISATION {self.OrganisationOVALDefinitionID}>'

class OVALDEFINITIONPLATFORM(Base):
    __tablename__ = 'OVALDEFINITIONPLATFORM'
    __bind_key__  = 'XOVAL'

    OVALDefinitionPlatformID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    PlatformID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONPLATFORM {self.OVALDefinitionPlatformID}>'

class OVALDEFINITIONPRODUCT(Base):
    __tablename__ = 'OVALDEFINITIONPRODUCT'
    __bind_key__  = 'XOVAL'

    OVALDefinitionProductID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    ProductID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONPRODUCT {self.OVALDefinitionProductID}>'

class OVALDEFINITIONREFERENCE(Base):
    __tablename__ = 'OVALDEFINITIONREFERENCE'
    __bind_key__  = 'XOVAL'

    OVALDefinitionReferenceID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    ReferenceID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONREFERENCE {self.OVALDefinitionReferenceID}>'

class OVALDEFINITIONS(Base):
    __tablename__ = 'OVALDEFINITIONS'
    __bind_key__  = 'XOVAL'

    OVALDefinitionsID = Column(Integer, primary_key=True)
    GeneratorTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALDEFINITIONS {self.OVALDefinitionsID}>'

class OVALDEFINITIONSTATUS(Base):
    __tablename__ = 'OVALDEFINITIONSTATUS'
    __bind_key__  = 'XOVAL'

    OVALDefinitionID = Column(Integer, primary_key=True)
    StatusID = Column(Integer, nullable=False)
    StatusDate = Column(Text)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<OVALDEFINITIONSTATUS {self.OVALDefinitionID}>'

class OVALDEFINITIONTAG(Base):
    __tablename__ = 'OVALDEFINITIONTAG'
    __bind_key__  = 'XOVAL'

    OVALDefinitionTagID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONTAG {self.OVALDefinitionTagID}>'

class OVALDEFINITIONTYPE(Base):
    __tablename__ = 'OVALDEFINITIONTYPE'
    __bind_key__  = 'XOVAL'

    OVALDefinitionTypeID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    OVALDefinitionIDPattern = Column(Text, nullable=False)
    OVALDefinitionVersion = Column(Integer, nullable=False)
    variable_instance = Column(Integer)
    OVALClassEnumerationID = Column(Integer)
    ClassValue = Column(Text)
    ResultEnumerationID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALDEFINITIONTYPE {self.OVALDefinitionTypeID}>'

class OVALDEFINITIONTYPEFOROVALSYSTEMTYPE(Base):
    __tablename__ = 'OVALDEFINITIONTYPEFOROVALSYSTEMTYPE'
    __bind_key__  = 'XOVAL'

    OVALSystemTypeID = Column(Integer, primary_key=True)
    OVALDefinitionTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALDEFINITIONTYPEFOROVALSYSTEMTYPE {self.OVALSystemTypeID}>'

class OVALDEFINITIONVULNERABILITY(Base):
    __tablename__ = 'OVALDEFINITIONVULNERABILITY'
    __bind_key__  = 'XOVAL'

    OVALDefinitionVulnerabilityID = Column(Integer, primary_key=True)
    OVALDefinitionID = Column(Integer)
    OVALDefinitionVulnerabilityRelationship = Column(Text)
    VulnerabilityID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALDEFINITIONVULNERABILITY {self.OVALDefinitionVulnerabilityID}>'

class OVALDIRECTIVE(Base):
    __tablename__ = 'OVALDIRECTIVE'
    __bind_key__  = 'XOVAL'

    OVALDirectiveID = Column(Integer, primary_key=True)
    reported = Column(Integer, nullable=False)
    ContentEnumerationValue = Column(Text)

    def __repr__(self):
        return f'<OVALDIRECTIVE {self.OVALDirectiveID}>'

class OVALDIRECTIVES(Base):
    __tablename__ = 'OVALDIRECTIVES'
    __bind_key__  = 'XOVAL'

    OVALDirectivesID = Column(Integer, primary_key=True)
    GeneratorTypeID = Column(Integer, nullable=False)
    OVALDefaultDirectivesID = Column(Integer, nullable=False)
    signature = Column(Text)

    def __repr__(self):
        return f'<OVALDIRECTIVES {self.OVALDirectivesID}>'

class OVALDIRECTIVESTYPE(Base):
    __tablename__ = 'OVALDIRECTIVESTYPE'
    __bind_key__  = 'XOVAL'

    OVALDirectivesTypeID = Column(Integer, primary_key=True)
    definition_trueOVALDirectiveID = Column(Integer, nullable=False)
    definition_falseOVALDirectiveID = Column(Integer, nullable=False)
    definition_unknownOVALDirectiveID = Column(Integer, nullable=False)
    definition_errorDirectiveID = Column(Integer, nullable=False)
    definition_not_evaluatedDirectiveID = Column(Integer, nullable=False)
    definition_not_applicableDirectiveID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALDIRECTIVESTYPE {self.OVALDirectivesTypeID}>'

class OVALENTITYATTRIBUTEGROUP(Base):
    __tablename__ = 'OVALENTITYATTRIBUTEGROUP'
    __bind_key__  = 'XOVAL'

    OVALEntityAttributeGroupID = Column(Integer, primary_key=True)
    SimpleDataTypeID = Column(Integer)
    DataTypeName = Column(Text)
    OperationEnumerationID = Column(Integer)
    OperationValue = Column(Text)
    mask = Column(Integer)
    OVALVariableID = Column(Integer)
    OVALVariableIDPattern = Column(Text)
    CheckEnumerationID = Column(Integer)
    EnumerationValue = Column(Text)

    def __repr__(self):
        return f'<OVALENTITYATTRIBUTEGROUP {self.OVALEntityAttributeGroupID}>'

class OVALENTITYCOMPLEXBASE(Base):
    __tablename__ = 'OVALENTITYCOMPLEXBASE'
    __bind_key__  = 'XOVAL'

    OVALEntityComplexBaseID = Column(Integer, primary_key=True)
    OVALEntityAttributeGroupID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALENTITYCOMPLEXBASE {self.OVALEntityComplexBaseID}>'

class OVALENTITYSIMPLEBASE(Base):
    __tablename__ = 'OVALENTITYSIMPLEBASE'
    __bind_key__  = 'XOVAL'

    OVALEntitySimpleBaseID = Column(Integer, primary_key=True)
    OVALEntityAttributeGroupID = Column(Integer, nullable=False)
    SimpleBaseValue = Column(Text)

    def __repr__(self):
        return f'<OVALENTITYSIMPLEBASE {self.OVALEntitySimpleBaseID}>'

class OVALEXTENSIONPOINT(Base):
    __tablename__ = 'OVALEXTENSIONPOINT'
    __bind_key__  = 'XOVAL'

    ExtensionPointID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<OVALEXTENSIONPOINT {self.ExtensionPointID}>'

class OVALEXTENSIONPOINTFOROVALGENERATORTYPE(Base):
    __tablename__ = 'OVALEXTENSIONPOINTFOROVALGENERATORTYPE'
    __bind_key__  = 'XOVAL'

    GeneratorTypeID = Column(Integer, primary_key=True)
    ExtensionPointID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALEXTENSIONPOINTFOROVALGENERATORTYPE {self.GeneratorTypeID}>'

class OVALEXTENSIONPOINTFORSYSTEMINFO(Base):
    __tablename__ = 'OVALEXTENSIONPOINTFORSYSTEMINFO'
    __bind_key__  = 'XOVAL'

    SystemInfoID = Column(Integer, primary_key=True)
    OVALExtensionPointID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALEXTENSIONPOINTFORSYSTEMINFO {self.SystemInfoID}>'

class OVALFILTER(Base):
    __tablename__ = 'OVALFILTER'
    __bind_key__  = 'XOVAL'

    OVALFilterID = Column(Integer, primary_key=True)
    OVALStateID = Column(Integer, nullable=False)
    FilterActionValue = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OVALFILTER {self.OVALFilterID}>'

class OVALFILTERFOROVALSET(Base):
    __tablename__ = 'OVALFILTERFOROVALSET'
    __bind_key__  = 'XOVAL'

    OVALSetID = Column(Integer, primary_key=True)
    OVALFilterID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALFILTERFOROVALSET {self.OVALSetID}>'

class OVALGENERATORTYPE(Base):
    __tablename__ = 'OVALGENERATORTYPE'
    __bind_key__  = 'XOVAL'

    GeneratorTypeID = Column(Integer, primary_key=True)
    productname = Column(Text)
    productversion = Column(Text)
    schemaversion = Column(Text, nullable=False)
    BLOB = Column(Text, nullable=False)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<OVALGENERATORTYPE {self.GeneratorTypeID}>'

class OVALITEM(Base):
    __tablename__ = 'OVALITEM'
    __bind_key__  = 'XOVAL'

    OVALItemID = Column(Integer, primary_key=True)
    OVALItemIDPattern = Column(Text, nullable=False)
    StatusID = Column(Integer)
    StatusName = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<OVALITEM {self.OVALItemID}>'

class OVALITEMATTRIBUTEGROUP(Base):
    __tablename__ = 'OVALITEMATTRIBUTEGROUP'
    __bind_key__  = 'XOVAL'

    OVALItemAttributeGroupID = Column(Integer, primary_key=True)
    DataTypeName = Column(Text)
    mask = Column(Integer)
    StatusName = Column(Text)
    OVALItemIDPattern = Column(Text)

    def __repr__(self):
        return f'<OVALITEMATTRIBUTEGROUP {self.OVALItemAttributeGroupID}>'

class OVALITEMCOMPLEXBASE(Base):
    __tablename__ = 'OVALITEMCOMPLEXBASE'
    __bind_key__  = 'XOVAL'

    OVALItemComplexBaseID = Column(Integer, primary_key=True)
    OVALItemAttributeGroupID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALITEMCOMPLEXBASE {self.OVALItemComplexBaseID}>'

class OVALITEMFOROVALSYSTEMOBJECT(Base):
    __tablename__ = 'OVALITEMFOROVALSYSTEMOBJECT'
    __bind_key__  = 'XOVAL'

    OVALSystemObjectID = Column(Integer, primary_key=True)
    OVALItemID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALITEMFOROVALSYSTEMOBJECT {self.OVALSystemObjectID}>'

class OVALITEMSIMPLEBASE(Base):
    __tablename__ = 'OVALITEMSIMPLEBASE'
    __bind_key__  = 'XOVAL'

    OVALItemSimpleBaseID = Column(Integer, primary_key=True)
    OVALItemAttributeGroupID = Column(Integer, nullable=False)
    EntityValue = Column(Text)

    def __repr__(self):
        return f'<OVALITEMSIMPLEBASE {self.OVALItemSimpleBaseID}>'

class OVALLITERALCOMPONENT(Base):
    __tablename__ = 'OVALLITERALCOMPONENT'
    __bind_key__  = 'XOVAL'

    OVALLiteralComponentID = Column(Integer, primary_key=True)
    SimpleDataTypeID = Column(Integer)
    LiteralComponentValue = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALLITERALCOMPONENT {self.OVALLiteralComponentID}>'

class OVALLITERALCOMPONENTFOROVALCOMPONENTGROUP(Base):
    __tablename__ = 'OVALLITERALCOMPONENTFOROVALCOMPONENTGROUP'
    __bind_key__  = 'XOVAL'

    OVALComponentGroupLiteralComponentID = Column(Integer, primary_key=True)
    OVALComponentGroupID = Column(Integer, nullable=False)
    OVALLiteralComponentID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALLITERALCOMPONENTFOROVALCOMPONENTGROUP {self.OVALComponentGroupLiteralComponentID}>'

class OVALMESSAGETYPE(Base):
    __tablename__ = 'OVALMESSAGETYPE'
    __bind_key__  = 'XOVAL'

    MessageTypeID = Column(Integer, primary_key=True)
    MessageLevelValue = Column(Text)
    MessageLevelID = Column(Integer)
    MessageText = Column(Text, nullable=False)

    def __repr__(self):
        return f'<OVALMESSAGETYPE {self.MessageTypeID}>'

class OVALMESSAGETYPEFOROVALDEFINITIONTYPE(Base):
    __tablename__ = 'OVALMESSAGETYPEFOROVALDEFINITIONTYPE'
    __bind_key__  = 'XOVAL'

    OVALDefinitionTypeID = Column(Integer, primary_key=True)
    OVALMessageTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALMESSAGETYPEFOROVALDEFINITIONTYPE {self.OVALDefinitionTypeID}>'

class OVALMESSAGETYPEFOROVALITEM(Base):
    __tablename__ = 'OVALMESSAGETYPEFOROVALITEM'
    __bind_key__  = 'XOVAL'

    OVALItemID = Column(Integer, primary_key=True)
    MessageTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALMESSAGETYPEFOROVALITEM {self.OVALItemID}>'

class OVALMESSAGETYPEFOROVALSYSTEMOBJECT(Base):
    __tablename__ = 'OVALMESSAGETYPEFOROVALSYSTEMOBJECT'
    __bind_key__  = 'XOVAL'

    OVALSystemObjectID = Column(Integer, primary_key=True)
    MessageTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALMESSAGETYPEFOROVALSYSTEMOBJECT {self.OVALSystemObjectID}>'

class OVALMESSAGETYPEFOROVALTESTEDITEM(Base):
    __tablename__ = 'OVALMESSAGETYPEFOROVALTESTEDITEM'
    __bind_key__  = 'XOVAL'

    OVALTestedItemID = Column(Integer, primary_key=True)
    MessageTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALMESSAGETYPEFOROVALTESTEDITEM {self.OVALTestedItemID}>'

class OVALMESSAGETYPEFOROVALTESTTYPE(Base):
    __tablename__ = 'OVALMESSAGETYPEFOROVALTESTTYPE'
    __bind_key__  = 'XOVAL'

    OVALTestTypeID = Column(Integer, primary_key=True)
    OVALMessageTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALMESSAGETYPEFOROVALTESTTYPE {self.OVALTestTypeID}>'

class OVALNAMESPACE(Base):
    __tablename__ = 'OVALNAMESPACE'
    __bind_key__  = 'XOVAL'

    OVALNamespaceID = Column(Integer, primary_key=True)
    OVALNamespaceName = Column(Text)
    OVALNamespaceDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALNAMESPACE {self.OVALNamespaceID}>'

class OVALOBJECT(Base):
    __tablename__ = 'OVALOBJECT'
    __bind_key__  = 'XOVAL'

    OVALObjectID = Column(Integer, primary_key=True)
    OVALObjectIDPattern = Column(Text, nullable=False)
    OVALObjectVersion = Column(Integer, nullable=False)
    OVALObjectGUID = Column(Text)
    comment = Column(Text, nullable=False)
    deprecated = Column(Integer)
    notes = Column(Text)
    signature = Column(Text)
    OVALObjectDataTypeID = Column(Integer)
    OVALNamespaceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECT {self.OVALObjectID}>'

class OVALOBJECTCOMPONENT(Base):
    __tablename__ = 'OVALOBJECTCOMPONENT'
    __bind_key__  = 'XOVAL'

    OVALObjectComponentID = Column(Integer, primary_key=True)
    OVALObjectID = Column(Integer, nullable=False)
    OVALItemEntityName = Column(Text, nullable=False)
    OVALItemEntityRecord = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTCOMPONENT {self.OVALObjectComponentID}>'

class OVALOBJECTCOMPONENTFOROVALCOMPONENTGROUP(Base):
    __tablename__ = 'OVALOBJECTCOMPONENTFOROVALCOMPONENTGROUP'
    __bind_key__  = 'XOVAL'

    OVALComponentGroupObjectComponentID = Column(Integer, primary_key=True)
    OVALComponentGroupID = Column(Integer, nullable=False)
    OVALObjectComponentID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTCOMPONENTFOROVALCOMPONENTGROUP {self.OVALComponentGroupObjectComponentID}>'

class OVALOBJECTDATATYPE(Base):
    __tablename__ = 'OVALOBJECTDATATYPE'
    __bind_key__  = 'XOVAL'

    OVALObjectDataTypeID = Column(Integer, primary_key=True)
    OVALObjectDataTypeName = Column(Text)
    OVALObjectDataTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTDATATYPE {self.OVALObjectDataTypeID}>'

class OVALOBJECTFIELD(Base):
    __tablename__ = 'OVALOBJECTFIELD'
    __bind_key__  = 'XOVAL'

    OVALObjectFieldID = Column(Integer, primary_key=True)
    OVALEntityAttributeGroupID = Column(Integer)
    FieldName = Column(Text, nullable=False)
    OperationEnumerationID = Column(Integer)
    FieldValue = Column(Text)
    DataTypeName = Column(Text)
    OVALNamespaceID = Column(Integer)
    Namespace = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    CheckEnumerationID = Column(Integer)
    OVALVariableID = Column(Integer)
    VarRef = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTFIELD {self.OVALObjectFieldID}>'

class OVALOBJECTFIELDFOROVALOBJECTRECORD(Base):
    __tablename__ = 'OVALOBJECTFIELDFOROVALOBJECTRECORD'
    __bind_key__  = 'XOVAL'

    OVALObjectRecordFieldID = Column(Integer, primary_key=True)
    OVALObjectRecordID = Column(Integer, nullable=False)
    OVALObjectFieldID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTFIELDFOROVALOBJECTRECORD {self.OVALObjectRecordFieldID}>'

class OVALOBJECTFILE(Base):
    __tablename__ = 'OVALOBJECTFILE'
    __bind_key__  = 'XOVAL'

    OVALObjectFileID = Column(Integer, primary_key=True)
    OVALObjectID = Column(Integer)
    FileID = Column(Integer)
    OVALVariableID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTFILE {self.OVALObjectFileID}>'

class OVALOBJECTFOROVALSET(Base):
    __tablename__ = 'OVALOBJECTFOROVALSET'
    __bind_key__  = 'XOVAL'

    OVALSetObjectID = Column(Integer, primary_key=True)
    OVALSetID = Column(Integer, nullable=False)
    OVALObjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTFOROVALSET {self.OVALSetObjectID}>'

class OVALOBJECTFOROVALTEST(Base):
    __tablename__ = 'OVALOBJECTFOROVALTEST'
    __bind_key__  = 'XOVAL'

    OVALTestObjectID = Column(Integer, primary_key=True)
    OVALTestID = Column(Integer, nullable=False)
    OVALObjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTFOROVALTEST {self.OVALTestObjectID}>'

class OVALOBJECTRECORD(Base):
    __tablename__ = 'OVALOBJECTRECORD'
    __bind_key__  = 'XOVAL'

    OVALObjectRecordID = Column(Integer, primary_key=True)
    OVALObjectDataTypeID = Column(Integer)
    OperationValue = Column(Text)
    mask = Column(Integer)
    OVALVariableIDPattern = Column(Text)
    EnumerationValue = Column(Text)
    OVALNamespaceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTRECORD {self.OVALObjectRecordID}>'

class OVALOBJECTRECORDFOROVALOBJECT(Base):
    __tablename__ = 'OVALOBJECTRECORDFOROVALOBJECT'
    __bind_key__  = 'XOVAL'

    OVALObjectObjectRecordID = Column(Integer, primary_key=True)
    OVALObjectID = Column(Integer, nullable=False)
    OVALObjectRecordID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTRECORDFOROVALOBJECT {self.OVALObjectObjectRecordID}>'

class OVALOBJECTTAG(Base):
    __tablename__ = 'OVALOBJECTTAG'
    __bind_key__  = 'XOVAL'

    OVALObjectTagID = Column(Integer, primary_key=True)
    OVALObjectID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTTAG {self.OVALObjectTagID}>'

class OVALOBJECTWINDOWSREGISTRYKEY(Base):
    __tablename__ = 'OVALOBJECTWINDOWSREGISTRYKEY'
    __bind_key__  = 'XOVAL'

    OVALObjectWindowsRegistryKeyID = Column(Integer, primary_key=True)
    OVALObjectID = Column(Integer, nullable=False)
    OVALObjectGUID = Column(Text)
    operation = Column(Text)
    WindowsRegistryKeyObjectID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALOBJECTWINDOWSREGISTRYKEY {self.OVALObjectWindowsRegistryKeyID}>'

class OVALRESULTS(Base):
    __tablename__ = 'OVALRESULTS'
    __bind_key__  = 'XOVAL'

    OVALResultsID = Column(Integer, primary_key=True)
    GeneratorTypeID = Column(Integer, nullable=False)
    OVALDefaultDirectivesID = Column(Integer, nullable=False)
    OVALDefinitionsID = Column(Integer)
    OVALResultsTypeID = Column(Integer, nullable=False)
    signature = Column(Text)

    def __repr__(self):
        return f'<OVALRESULTS {self.OVALResultsID}>'

class OVALRESULTSTYPE(Base):
    __tablename__ = 'OVALRESULTSTYPE'
    __bind_key__  = 'XOVAL'

    OVALResultsTypeId = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<OVALRESULTSTYPE {self.OVALResultsTypeId}>'

class OVALSET(Base):
    __tablename__ = 'OVALSET'
    __bind_key__  = 'XOVAL'

    OVALSetID = Column(Integer, primary_key=True)
    SetOperatorValue = Column(Text)

    def __repr__(self):
        return f'<OVALSET {self.OVALSetID}>'

class OVALSETFOROVALSET(Base):
    __tablename__ = 'OVALSETFOROVALSET'
    __bind_key__  = 'XOVAL'

    OVALSetRefID = Column(Integer, primary_key=True)
    OVALSetSubjectID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALSETFOROVALSET {self.OVALSetRefID}>'

class OVALSTATE(Base):
    __tablename__ = 'OVALSTATE'
    __bind_key__  = 'XOVAL'

    OVALStateID = Column(Integer, primary_key=True)
    OVALStateIDPattern = Column(Text, nullable=False)
    OVALStateVersion = Column(Integer)
    OVALStateSimpleBaseID = Column(Integer)
    OVALStateComplexBaseID = Column(Integer)
    OVALStateTypeID = Column(Integer)
    DataTypeName = Column(Text)
    OperatorEnumerationID = Column(Integer)
    comment = Column(Text, nullable=False)
    deprecated = Column(Integer)
    notes = Column(Text)
    signature = Column(Text)
    OVALNamespaceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALSTATE {self.OVALStateID}>'

class OVALSTATECOMPLEXBASE(Base):
    __tablename__ = 'OVALSTATECOMPLEXBASE'
    __bind_key__  = 'XOVAL'

    OVALStateComplexBaseID = Column(Integer, primary_key=True)
    CheckEnumerationID = Column(Integer)
    EnumerationValue = Column(Text)
    DataTypeName = Column(Text)

    def __repr__(self):
        return f'<OVALSTATECOMPLEXBASE {self.OVALStateComplexBaseID}>'

class OVALSTATEFIELD(Base):
    __tablename__ = 'OVALSTATEFIELD'
    __bind_key__  = 'XOVAL'

    OVALStateFieldID = Column(Integer, primary_key=True)
    OVALEntityAttributeGroupID = Column(Integer)
    FieldName = Column(Text)
    DataTypeName = Column(Text)
    OperationEnumerationID = Column(Integer)
    CheckEnumerationID = Column(Integer)
    FieldValue = Column(Text)
    OVALNamespaceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    OVALVariableID = Column(Integer)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALSTATEFIELD {self.OVALStateFieldID}>'

class OVALSTATEFIELDFOROVALSTATERECORD(Base):
    __tablename__ = 'OVALSTATEFIELDFOROVALSTATERECORD'
    __bind_key__  = 'XOVAL'

    OVALStateRecordStateFieldID = Column(Integer, primary_key=True)
    OVALStateRecordID = Column(Integer, nullable=False)
    OVALStateFieldID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALSTATEFIELDFOROVALSTATERECORD {self.OVALStateRecordStateFieldID}>'

class OVALSTATEFOROVALTEST(Base):
    __tablename__ = 'OVALSTATEFOROVALTEST'
    __bind_key__  = 'XOVAL'

    OVALTestStateID = Column(Integer, primary_key=True)
    OVALTestID = Column(Integer, nullable=False)
    OVALStateID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALSTATEFOROVALTEST {self.OVALTestStateID}>'

class OVALSTATERECORD(Base):
    __tablename__ = 'OVALSTATERECORD'
    __bind_key__  = 'XOVAL'

    OVALStateRecordID = Column(Integer, primary_key=True)
    OVALStateComplexBaseID = Column(Integer)
    OVALStateTypeID = Column(Integer)
    DataTypeName = Column(Text, nullable=False)
    OperationEnumerationID = Column(Integer)
    mask = Column(Integer)
    OVALVariableID = Column(Integer)
    CheckEnumerationID = Column(Integer)
    OVALNamespaceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALSTATERECORD {self.OVALStateRecordID}>'

class OVALSTATERECORDFOROVALSTATE(Base):
    __tablename__ = 'OVALSTATERECORDFOROVALSTATE'
    __bind_key__  = 'XOVAL'

    OVALStateStateRecordID = Column(Integer, primary_key=True)
    OVALStateID = Column(Integer, nullable=False)
    OVALStateRecordID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALSTATERECORDFOROVALSTATE {self.OVALStateStateRecordID}>'

class OVALSTATESIMPLEBASE(Base):
    __tablename__ = 'OVALSTATESIMPLEBASE'
    __bind_key__  = 'XOVAL'

    OVALStateSimpleBaseID = Column(Integer, primary_key=True)
    CheckEnumerationID = Column(Integer)
    EnumerationValue = Column(Text)
    EntityValue = Column(Text)
    DataTypeName = Column(Text)

    def __repr__(self):
        return f'<OVALSTATESIMPLEBASE {self.OVALStateSimpleBaseID}>'

class OVALSTATETYPE(Base):
    __tablename__ = 'OVALSTATETYPE'
    __bind_key__  = 'XOVAL'

    OVALStateTypeID = Column(Integer, primary_key=True)
    OVALStateTypeName = Column(Text)
    OVALStateTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALSTATETYPE {self.OVALStateTypeID}>'

class OVALSYSTEMCHARACTERISTICS(Base):
    __tablename__ = 'OVALSYSTEMCHARACTERISTICS'
    __bind_key__  = 'XOVAL'

    OVALSystemCharacteristicsID = Column(Integer, primary_key=True)
    GeneratorTypeID = Column(Integer, nullable=False)
    signature = Column(Text)

    def __repr__(self):
        return f'<OVALSYSTEMCHARACTERISTICS {self.OVALSystemCharacteristicsID}>'

class OVALSYSTEMOBJECT(Base):
    __tablename__ = 'OVALSYSTEMOBJECT'
    __bind_key__  = 'XOVAL'

    OVALSystemObjectID = Column(Integer, primary_key=True)
    OVALObjectID = Column(Integer, nullable=False)
    OVALObjectIDPattern = Column(Text, nullable=False)
    OVALObjectVersion = Column(Integer, nullable=False)
    VariableInstance = Column(Integer)
    comment = Column(Text)
    FlagID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALSYSTEMOBJECT {self.OVALSystemObjectID}>'

class OVALSYSTEMTYPE(Base):
    __tablename__ = 'OVALSYSTEMTYPE'
    __bind_key__  = 'XOVAL'

    OVALSystemTypeID = Column(Integer, primary_key=True)
    OVALSystemCharacteristicsID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALSYSTEMTYPE {self.OVALSystemTypeID}>'

class OVALSYSTEMTYPEFOROVALRESULTSTYPE(Base):
    __tablename__ = 'OVALSYSTEMTYPEFOROVALRESULTSTYPE'
    __bind_key__  = 'XOVAL'

    OVALResultsTypeID = Column(Integer, primary_key=True)
    OVALSystemTypeID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALSYSTEMTYPEFOROVALRESULTSTYPE {self.OVALResultsTypeID}>'

class OVALTEST(Base):
    __tablename__ = 'OVALTEST'
    __bind_key__  = 'XOVAL'

    OVALTestID = Column(Integer, primary_key=True)
    OVALTestIDPattern = Column(Text, nullable=False)
    OVALTestVersion = Column(Integer, nullable=False)
    ExistenceEnumerationID = Column(Integer)
    CheckEnumerationID = Column(Integer)
    OperatorEnumerationID = Column(Integer)
    comment = Column(Text, nullable=False)
    deprecated = Column(Integer)
    notes = Column(Text)
    signature = Column(Text)
    OVALTestDataTypeID = Column(Integer)
    OVALNamespaceID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    RepositoryID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALTEST {self.OVALTestID}>'

class OVALTESTDATATYPE(Base):
    __tablename__ = 'OVALTESTDATATYPE'
    __bind_key__  = 'XOVAL'

    OVALTestDataTypeID = Column(Integer, primary_key=True)
    OVALTestDataTypeName = Column(Text)
    OVALTestDataTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALTESTDATATYPE {self.OVALTestDataTypeID}>'

class OVALTESTEDITEM(Base):
    __tablename__ = 'OVALTESTEDITEM'
    __bind_key__  = 'XOVAL'

    OVALTestedItemID = Column(Integer, primary_key=True)
    OVALItemID = Column(Integer)
    OVALItemIDPattern = Column(Text, nullable=False)
    ResultEnumerationID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALTESTEDITEM {self.OVALTestedItemID}>'

class OVALTESTEDITEMFOROVALTESTTYPE(Base):
    __tablename__ = 'OVALTESTEDITEMFOROVALTESTTYPE'
    __bind_key__  = 'XOVAL'

    OVALTestTypeID = Column(Integer, primary_key=True)
    OVALTestedItemID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALTESTEDITEMFOROVALTESTTYPE {self.OVALTestTypeID}>'

class OVALTESTEDVARIABLE(Base):
    __tablename__ = 'OVALTESTEDVARIABLE'
    __bind_key__  = 'XOVAL'

    OVALTestedVariableID = Column(Integer, primary_key=True)
    OVALVariableID = Column(Integer)
    OVALVariableIDPattern = Column(Text, nullable=False)
    OVALVariableValue = Column(Text, nullable=False)

    def __repr__(self):
        return f'<OVALTESTEDVARIABLE {self.OVALTestedVariableID}>'

class OVALTESTEDVARIABLEFOROVALTESTTYPE(Base):
    __tablename__ = 'OVALTESTEDVARIABLEFOROVALTESTTYPE'
    __bind_key__  = 'XOVAL'

    OVALTestTypeID = Column(Integer, primary_key=True)
    OVALTestedVariableId = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALTESTEDVARIABLEFOROVALTESTTYPE {self.OVALTestTypeID}>'

class OVALTESTFOROVALTESTS(Base):
    __tablename__ = 'OVALTESTFOROVALTESTS'
    __bind_key__  = 'XOVAL'

    OVALTestsTestID = Column(Integer, primary_key=True)
    OVALTestsID = Column(Integer, nullable=False)
    OVALTestID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALTESTFOROVALTESTS {self.OVALTestsTestID}>'

class OVALTESTS(Base):
    __tablename__ = 'OVALTESTS'
    __bind_key__  = 'XOVAL'

    OVALTestsID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<OVALTESTS {self.OVALTestsID}>'

class OVALTESTTAG(Base):
    __tablename__ = 'OVALTESTTAG'
    __bind_key__  = 'XOVAL'

    OVALTestTagID = Column(Integer, primary_key=True)
    OVALTestID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALTESTTAG {self.OVALTestTagID}>'

class OVALTESTTYPE(Base):
    __tablename__ = 'OVALTESTTYPE'
    __bind_key__  = 'XOVAL'

    OVALTestTypeID = Column(Integer, primary_key=True)
    OVALTestID = Column(Integer)
    OVALTestIDPattern = Column(Text, nullable=False)
    OVALTestVersion = Column(Integer, nullable=False)
    variable_instance = Column(Integer)
    ExistenceEnumerationID = Column(Integer)
    ExistenceValue = Column(Text)
    CheckEnumerationID = Column(Integer)
    EnumerationValue = Column(Text, nullable=False)
    OperatorEnumerationID = Column(Integer)
    OperatorValue = Column(Text)
    ResultEnumerationID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALTESTTYPE {self.OVALTestTypeID}>'

class OVALTESTTYPEFOROVALSYSTEMTYPE(Base):
    __tablename__ = 'OVALTESTTYPEFOROVALSYSTEMTYPE'
    __bind_key__  = 'XOVAL'

    OVALSystemTypeTestTypeID = Column(Integer, primary_key=True)
    OVALSystemTypeID = Column(Integer, nullable=False)
    OVALTestTypeID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALTESTTYPEFOROVALSYSTEMTYPE {self.OVALSystemTypeTestTypeID}>'

class OVALVARIABLE(Base):
    __tablename__ = 'OVALVARIABLE'
    __bind_key__  = 'XOVAL'

    OVALVariableID = Column(Integer, primary_key=True)
    OVALVariableIDPattern = Column(Text, nullable=False)
    OVALVariableVersion = Column(Integer, nullable=False)
    OVALVariableDataTypeID = Column(Integer)
    comment = Column(Text, nullable=False)
    deprecated = Column(Integer)
    signature = Column(Text)
    OVALNamespaceID = Column(Integer)
    OVALVariableTypeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALVARIABLE {self.OVALVariableID}>'

class OVALVARIABLECOMPONENT(Base):
    __tablename__ = 'OVALVARIABLECOMPONENT'
    __bind_key__  = 'XOVAL'

    OVALVariableComponentID = Column(Integer, primary_key=True)
    OVALVariableID = Column(Integer, nullable=False)
    OVALItemFieldName = Column(Text)
    OVALObjectRefID = Column(Integer)
    OVALVariableRefID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALVARIABLECOMPONENT {self.OVALVariableComponentID}>'

class OVALVARIABLECOMPONENTFOROVALCOMPONENTGROUP(Base):
    __tablename__ = 'OVALVARIABLECOMPONENTFOROVALCOMPONENTGROUP'
    __bind_key__  = 'XOVAL'

    OVALComponentGroupVariableComponentID = Column(Integer, primary_key=True)
    OVALComponentGroupID = Column(Integer, nullable=False)
    OVALVariableComponentID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OVALVARIABLECOMPONENTFOROVALCOMPONENTGROUP {self.OVALComponentGroupVariableComponentID}>'

class OVALVARIABLEDATATYPE(Base):
    __tablename__ = 'OVALVARIABLEDATATYPE'
    __bind_key__  = 'XOVAL'

    OVALVariableDataTypeID = Column(Integer, primary_key=True)
    OVALVariableDataTypeName = Column(Text)
    OVALVariableDataTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALVARIABLEDATATYPE {self.OVALVariableDataTypeID}>'

class OVALVARIABLEFOROVALVARIABLES(Base):
    __tablename__ = 'OVALVARIABLEFOROVALVARIABLES'
    __bind_key__  = 'XOVAL'

    OVALVariablesID = Column(Integer, primary_key=True)
    OVALVariableID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<OVALVARIABLEFOROVALVARIABLES {self.OVALVariablesID}>'

class OVALVARIABLES(Base):
    __tablename__ = 'OVALVARIABLES'
    __bind_key__  = 'XOVAL'

    OVALVariablesID = Column(Integer, primary_key=True)
    OVALGeneratorTypeID = Column(Integer, nullable=False)
    signature = Column(Text)

    def __repr__(self):
        return f'<OVALVARIABLES {self.OVALVariablesID}>'

class OVALVARIABLETAG(Base):
    __tablename__ = 'OVALVARIABLETAG'
    __bind_key__  = 'XOVAL'

    OVALVariableTagID = Column(Integer, primary_key=True)
    OVALVariableID = Column(Integer)
    TagID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALVARIABLETAG {self.OVALVariableTagID}>'

class OVALVARIABLETYPE(Base):
    __tablename__ = 'OVALVARIABLETYPE'
    __bind_key__  = 'XOVAL'

    OVALVariableTypeID = Column(Integer, primary_key=True)
    OVALVariableTypeName = Column(Text)
    OVALVariableTypeDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<OVALVARIABLETYPE {self.OVALVariableTypeID}>'

class OVALVARIABLEVALUE(Base):
    __tablename__ = 'OVALVARIABLEVALUE'
    __bind_key__  = 'XOVAL'

    OVALVariableValueID = Column(Integer, primary_key=True)
    OVALVariableID = Column(Integer, nullable=False)
    OVALVariableGUID = Column(Text)
    ValueID = Column(Integer, nullable=False)
    ValueValue = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<OVALVARIABLEVALUE {self.OVALVariableValueID}>'

class OVALVARIABLEVALUEFOROVALSYSTEMOBJECT(Base):
    __tablename__ = 'OVALVARIABLEVALUEFOROVALSYSTEMOBJECT'
    __bind_key__  = 'XOVAL'

    OVALSystemObjectVariableValueID = Column(Integer, primary_key=True)
    OVALSystemObjectID = Column(Integer, nullable=False)
    OVALVariableValueID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<OVALVARIABLEVALUEFOROVALSYSTEMOBJECT {self.OVALSystemObjectVariableValueID}>'
