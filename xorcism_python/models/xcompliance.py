"""
xcompliance.py — Models of the XCOMPLIANCE database (audits, findings, reports).

Tables:
  AUDIT         — an audit (status, auditor, scope, type, dates)
  AUDITFINDING  — an audit finding (criticality, status, stakeholder)
  AUDITREPORT   — an audit report (author, client, status)
  EVIDENCE      — a compliance evidence (URL, validity, dates)
  AUDITEVIDENCE — audit ↔ evidence link (status, confidence level)
  DOCUMENT      — a compliance document (URL, author, validity, dates)
  AUDITDOCUMENT — audit ↔ document link (confidence level, validity)
  DOCUMENTPERSON— document ↔ person link (role, validity)
"""
from sqlalchemy import Column, Integer, Text, Float
from sqlalchemy.orm import DeclarativeBase


class ComplianceBase(DeclarativeBase):
    """ISOLATED MetaData for XCOMPLIANCE.

    AUDIT/AUDITFINDING tables already exist in XORCISM.db under the shared
    Base (xorcism.py). Since all the models share a single MetaData,
    reusing these names there would cause a conflict. XCOMPLIANCE therefore has its own
    declarative base; the routing to the right database happens anyway
    via session_scope('XCOMPLIANCE') (dedicated engine), not via the MetaData.
    """
    pass


class AUDIT(ComplianceBase):
    __tablename__ = 'AUDIT'
    __bind_key__ = 'XCOMPLIANCE'

    AuditID = Column(Integer, primary_key=True)
    AuditGUID = Column(Text)
    AuditName = Column(Text)
    AuditDate = Column(Text)            # date (ISO 'YYYY-MM-DD')
    AuditStatus = Column(Text)
    AuditorName = Column(Text)
    AuditDescription = Column(Text)
    AuditCategory = Column(Text)
    AuditScope = Column(Text)
    AuditType = Column(Text)
    AuditClosureDate = Column(Text)     # date
    TenantID = Column(Integer)          # multi-tenant partitioning (TENANT_SCOPED_TABLES)

    def __repr__(self):
        return f'<AUDIT {self.AuditID}>'


class AUDITFINDING(ComplianceBase):
    __tablename__ = 'AUDITFINDING'
    __bind_key__ = 'XCOMPLIANCE'

    AuditFindingID = Column(Integer, primary_key=True)
    AuditFindingGUID = Column(Text)
    FindingName = Column(Text)
    FindingDescription = Column(Text)
    FindingDate = Column(Text)          # date
    FindingStatus = Column(Text)
    FindingStakeholder = Column(Text)
    FindingCriticity = Column(Text)

    def __repr__(self):
        return f'<AUDITFINDING {self.AuditFindingID}>'


class AUDITREPORT(ComplianceBase):
    __tablename__ = 'AUDITREPORT'
    __bind_key__ = 'XCOMPLIANCE'

    AuditReportID = Column(Integer, primary_key=True)
    AuditReportGUID = Column(Text)
    ReportName = Column(Text)
    ReportDescription = Column(Text)
    ReportDate = Column(Text)           # date
    ReportAuthor = Column(Text)
    ReportClient = Column(Text)
    ReportStatus = Column(Text)
    PersonID = Column(Integer)  # author/owner (PERSON reference)

    def __repr__(self):
        return f'<AUDITREPORT {self.AuditReportID}>'


class EVIDENCE(ComplianceBase):
    __tablename__ = 'EVIDENCE'
    __bind_key__ = 'XCOMPLIANCE'

    EvidenceID = Column(Integer, primary_key=True)
    EvidenceName = Column(Text)
    EvidenceDescription = Column(Text)
    EvidenceDate = Column(Text)         # date (ISO 'YYYY-MM-DD')
    CreatedDate = Column(Text)          # date
    ValidFrom = Column(Text)            # date
    ValidUntil = Column(Text)           # date
    EvidenceURL = Column(Text)
    Validity = Column(Text)
    EvidenceFile = Column(Text)         # URL of the uploaded file (/uploads/...)

    def __repr__(self):
        return f'<EVIDENCE {self.EvidenceID}>'


class AUDITEVIDENCE(ComplianceBase):
    __tablename__ = 'AUDITEVIDENCE'
    __bind_key__ = 'XCOMPLIANCE'

    AuditEvidenceID = Column(Integer, primary_key=True)
    AuditEvidenceGUID = Column(Text)
    AuditID = Column(Integer)           # AUDIT reference
    EvidenceID = Column(Integer)        # EVIDENCE reference
    CreatedDate = Column(Text)          # date
    ConfidenceLevel = Column(Text)
    Status = Column(Text)

    def __repr__(self):
        return f'<AUDITEVIDENCE {self.AuditEvidenceID}>'


class DOCUMENT(ComplianceBase):
    __tablename__ = 'DOCUMENT'
    __bind_key__ = 'XCOMPLIANCE'

    DocumentID = Column(Integer, primary_key=True)
    DocumentGUID = Column(Text)
    DocumentName = Column(Text)
    DocumentDescription = Column(Text)
    DocumentDate = Column(Text)         # date (ISO 'YYYY-MM-DD')
    Author = Column(Text)
    ValidFrom = Column(Text)            # date
    ValidUntil = Column(Text)           # date
    DocumentURL = Column(Text)
    Version = Column(Text)
    DocumentFile = Column(Text)         # URL of the uploaded file (/uploads/...)

    def __repr__(self):
        return f'<DOCUMENT {self.DocumentID}>'


class AUDITDOCUMENT(ComplianceBase):
    __tablename__ = 'AUDITDOCUMENT'
    __bind_key__ = 'XCOMPLIANCE'

    AuditDocumentID = Column(Integer, primary_key=True)
    AuditID = Column(Integer)           # AUDIT reference
    DocumentID = Column(Integer)        # DOCUMENT reference
    CreatedDate = Column(Text)          # date
    ConfidenceLevel = Column(Text)
    ValidFrom = Column(Text)            # date
    ValidUntil = Column(Text)           # date

    def __repr__(self):
        return f'<AUDITDOCUMENT {self.AuditDocumentID}>'


class DOCUMENTPERSON(ComplianceBase):
    __tablename__ = 'DOCUMENTPERSON'
    __bind_key__ = 'XCOMPLIANCE'

    DocumentPersonID = Column(Integer, primary_key=True)
    DocumentID = Column(Integer)        # DOCUMENT reference
    PersonID = Column(Integer)          # PERSON reference (XORCISM database)
    Role = Column(Text)
    CreatedDate = Column(Text)          # date
    ValidFrom = Column(Text)            # date
    ValidUntil = Column(Text)           # date

    def __repr__(self):
        return f'<DOCUMENTPERSON {self.DocumentPersonID}>'


# ── GRC (Governance, Risk & Compliance) — model inspired by CISO Assistant ─────────
# Scopes/folders, frameworks + requirements, controls, compliance assessments
# and risk assessments, risk scenarios, acceptances and exceptions.

class FOLDER(ComplianceBase):
    __tablename__ = 'FOLDER'
    __bind_key__ = 'XCOMPLIANCE'

    FolderID = Column(Integer, primary_key=True)
    FolderGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    ParentFolderID = Column(Integer)
    ContentType = Column(Text)       # 'ROOT' | 'DOMAIN' | 'ENCLAVE'
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<FOLDER {self.FolderID}>'


class PERIMETER(ComplianceBase):
    __tablename__ = 'PERIMETER'
    __bind_key__ = 'XCOMPLIANCE'

    PerimeterID = Column(Integer, primary_key=True)
    PerimeterGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    FolderID = Column(Integer)
    Ref = Column(Text)
    Status = Column(Text)
    LifecycleStatus = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<PERIMETER {self.PerimeterID}>'


class FRAMEWORK(ComplianceBase):
    __tablename__ = 'FRAMEWORK'
    __bind_key__ = 'XCOMPLIANCE'

    FrameworkID = Column(Integer, primary_key=True)
    FrameworkGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    Provider = Column(Text)
    Version = Column(Text)
    URN = Column(Text)
    Ref = Column(Text)
    Locale = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<FRAMEWORK {self.FrameworkID}>'


class REQUIREMENTNODE(ComplianceBase):
    __tablename__ = 'REQUIREMENTNODE'
    __bind_key__ = 'XCOMPLIANCE'

    RequirementNodeID = Column(Integer, primary_key=True)
    RequirementNodeGUID = Column(Text)
    FrameworkID = Column(Integer)
    ParentRequirementNodeID = Column(Integer)
    URN = Column(Text)
    Ref = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    OrderID = Column(Integer)
    Depth = Column(Integer)
    Assessable = Column(Integer)
    CreatedDate = Column(Text)

    TenantID = Column(Integer)

    def __repr__(self):
        return f'<REQUIREMENTNODE {self.RequirementNodeID}>'


class REFERENCECONTROL(ComplianceBase):
    __tablename__ = 'REFERENCECONTROL'
    __bind_key__ = 'XCOMPLIANCE'

    ReferenceControlID = Column(Integer, primary_key=True)
    ReferenceControlGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    Category = Column(Text)          # technical | process | physical | policy
    Function = Column(Text)          # govern | identify | protect | detect | respond | recover
    Provider = Column(Text)
    URN = Column(Text)
    Ref = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<REFERENCECONTROL {self.ReferenceControlID}>'


class APPLIEDCONTROL(ComplianceBase):
    __tablename__ = 'APPLIEDCONTROL'
    __bind_key__ = 'XCOMPLIANCE'

    AppliedControlID = Column(Integer, primary_key=True)
    AppliedControlGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    ReferenceControlID = Column(Integer)
    Category = Column(Text)
    Function = Column(Text)
    Status = Column(Text)            # to_do | in_progress | on_hold | active | deprecated
    Priority = Column(Integer)
    Effort = Column(Text)            # S | M | L | XL
    Cost = Column(Float)
    OwnerPersonID = Column(Integer)
    FolderID = Column(Integer)
    StartDate = Column(Text)
    ETA = Column(Text)
    ExpiryDate = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<APPLIEDCONTROL {self.AppliedControlID}>'


class COMPLIANCEASSESSMENT(ComplianceBase):
    __tablename__ = 'COMPLIANCEASSESSMENT'
    __bind_key__ = 'XCOMPLIANCE'

    ComplianceAssessmentID = Column(Integer, primary_key=True)
    ComplianceAssessmentGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    FrameworkID = Column(Integer)
    PerimeterID = Column(Integer)
    Status = Column(Text)            # planned | in_progress | in_review | done | deprecated
    Version = Column(Text)
    AuthorPersonID = Column(Integer)
    Date = Column(Text)
    DueDate = Column(Text)
    Score = Column(Integer)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<COMPLIANCEASSESSMENT {self.ComplianceAssessmentID}>'


class REQUIREMENTASSESSMENT(ComplianceBase):
    __tablename__ = 'REQUIREMENTASSESSMENT'
    __bind_key__ = 'XCOMPLIANCE'

    RequirementAssessmentID = Column(Integer, primary_key=True)
    RequirementAssessmentGUID = Column(Text)
    ComplianceAssessmentID = Column(Integer)
    RequirementNodeID = Column(Integer)
    Status = Column(Text)            # to_do | in_progress | in_review | done
    Result = Column(Text)            # compliant | partially_compliant | non_compliant | not_applicable
    Score = Column(Integer)
    IsScored = Column(Integer)
    Observation = Column(Text)
    CreatedDate = Column(Text)

    TenantID = Column(Integer)

    def __repr__(self):
        return f'<REQUIREMENTASSESSMENT {self.RequirementAssessmentID}>'


class REQUIREMENTASSESSMENTCONTROL(ComplianceBase):
    __tablename__ = 'REQUIREMENTASSESSMENTCONTROL'
    __bind_key__ = 'XCOMPLIANCE'

    RequirementAssessmentControlID = Column(Integer, primary_key=True)
    RequirementAssessmentID = Column(Integer)
    AppliedControlID = Column(Integer)
    CreatedDate = Column(Text)

    TenantID = Column(Integer)

    def __repr__(self):
        return f'<REQUIREMENTASSESSMENTCONTROL {self.RequirementAssessmentControlID}>'


class REQUIREMENTASSESSMENTEVIDENCE(ComplianceBase):
    __tablename__ = 'REQUIREMENTASSESSMENTEVIDENCE'
    __bind_key__ = 'XCOMPLIANCE'

    RequirementAssessmentEvidenceID = Column(Integer, primary_key=True)
    RequirementAssessmentID = Column(Integer)
    EvidenceID = Column(Integer)
    CreatedDate = Column(Text)

    TenantID = Column(Integer)

    def __repr__(self):
        return f'<REQUIREMENTASSESSMENTEVIDENCE {self.RequirementAssessmentEvidenceID}>'


class RISKMATRIX(ComplianceBase):
    __tablename__ = 'RISKMATRIX'
    __bind_key__ = 'XCOMPLIANCE'

    RiskMatrixID = Column(Integer, primary_key=True)
    RiskMatrixGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    Definition = Column(Text)        # JSON: probabilities, impacts, risk grid
    ProbabilityCount = Column(Integer)
    ImpactCount = Column(Integer)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKMATRIX {self.RiskMatrixID}>'


class RISKASSESSMENT(ComplianceBase):
    __tablename__ = 'RISKASSESSMENT'
    __bind_key__ = 'XCOMPLIANCE'

    RiskAssessmentID = Column(Integer, primary_key=True)
    RiskAssessmentGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    PerimeterID = Column(Integer)
    RiskMatrixID = Column(Integer)
    Status = Column(Text)
    Version = Column(Text)
    AuthorPersonID = Column(Integer)
    Date = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKASSESSMENT {self.RiskAssessmentID}>'


class RISKSCENARIO(ComplianceBase):
    __tablename__ = 'RISKSCENARIO'
    __bind_key__ = 'XCOMPLIANCE'

    RiskScenarioID = Column(Integer, primary_key=True)
    RiskScenarioGUID = Column(Text)
    RiskAssessmentID = Column(Integer)
    Ref = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    ThreatID = Column(Integer)
    ThreatName = Column(Text)
    ExistingControls = Column(Text)
    CurrentProbability = Column(Integer)
    CurrentImpact = Column(Integer)
    CurrentRiskLevel = Column(Integer)
    ResidualProbability = Column(Integer)
    ResidualImpact = Column(Integer)
    ResidualRiskLevel = Column(Integer)
    TreatmentStrategy = Column(Text)  # accept | avoid | transfer | mitigate
    Justification = Column(Text)
    Status = Column(Text)
    CreatedDate = Column(Text)

    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKSCENARIO {self.RiskScenarioID}>'


class RISKSCENARIOCONTROL(ComplianceBase):
    __tablename__ = 'RISKSCENARIOCONTROL'
    __bind_key__ = 'XCOMPLIANCE'

    RiskScenarioControlID = Column(Integer, primary_key=True)
    RiskScenarioID = Column(Integer)
    AppliedControlID = Column(Integer)
    CreatedDate = Column(Text)

    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKSCENARIOCONTROL {self.RiskScenarioControlID}>'


class RISKSCENARIOASSET(ComplianceBase):
    __tablename__ = 'RISKSCENARIOASSET'
    __bind_key__ = 'XCOMPLIANCE'

    RiskScenarioAssetID = Column(Integer, primary_key=True)
    RiskScenarioID = Column(Integer)
    AssetID = Column(Integer)        # ASSET reference (XORCISM database)
    CreatedDate = Column(Text)

    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKSCENARIOASSET {self.RiskScenarioAssetID}>'


class RISKACCEPTANCE(ComplianceBase):
    __tablename__ = 'RISKACCEPTANCE'
    __bind_key__ = 'XCOMPLIANCE'

    RiskAcceptanceID = Column(Integer, primary_key=True)
    RiskAcceptanceGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    RiskScenarioID = Column(Integer)
    ApproverPersonID = Column(Integer)
    Status = Column(Text)            # draft | submitted | accepted | rejected | revoked
    Justification = Column(Text)
    AcceptedDate = Column(Text)
    ExpiryDate = Column(Text)
    RevokedDate = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKACCEPTANCE {self.RiskAcceptanceID}>'


class SECURITYEXCEPTION(ComplianceBase):
    __tablename__ = 'SECURITYEXCEPTION'
    __bind_key__ = 'XCOMPLIANCE'

    SecurityExceptionID = Column(Integer, primary_key=True)
    SecurityExceptionGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    Ref = Column(Text)
    Status = Column(Text)            # draft | submitted | approved | expired | deprecated
    Severity = Column(Text)
    OwnerPersonID = Column(Integer)
    ApproverPersonID = Column(Integer)
    ExpiryDate = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<SECURITYEXCEPTION {self.SecurityExceptionID}>'


class GRCTHREAT(ComplianceBase):
    __tablename__ = 'GRCTHREAT'
    __bind_key__ = 'XCOMPLIANCE'

    ThreatID = Column(Integer, primary_key=True)
    ThreatGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    Provider = Column(Text)
    URN = Column(Text)
    Ref = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<GRCTHREAT {self.ThreatID}>'


# ── Risk Register + links to XORCISM ───────────────────

class RISKREGISTER(ComplianceBase):
    __tablename__ = 'RISKREGISTER'
    __bind_key__ = 'XCOMPLIANCE'

    RiskRegisterID = Column(Integer, primary_key=True)
    RiskRegisterGUID = Column(Text)
    Name = Column(Text)
    Description = Column(Text)
    PerimeterID = Column(Integer)         # PERIMETER reference
    OwnerPersonID = Column(Integer)       # PERSON reference (XORCISM database)
    Status = Column(Text)                 # active | draft | archived
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKREGISTER {self.RiskRegisterID}>'


class RISKREGISTERENTRY(ComplianceBase):
    __tablename__ = 'RISKREGISTERENTRY'
    __bind_key__ = 'XCOMPLIANCE'

    RiskRegisterEntryID = Column(Integer, primary_key=True)
    RiskRegisterEntryGUID = Column(Text)
    RiskRegisterID = Column(Integer)      # RISKREGISTER reference
    Ref = Column(Text)                    # risk identifier (e.g. R-001)
    Title = Column(Text)
    Description = Column(Text)
    Category = Column(Text)
    RiskOwnerPersonID = Column(Integer)   # PERSON reference (XORCISM database)
    AssetID = Column(Integer)             # main asset (XORCISM database)
    ThreatID = Column(Integer)
    ThreatName = Column(Text)
    VulnerabilityID = Column(Integer)     # VULNERABILITY reference (XVULNERABILITY database)
    InherentProbability = Column(Integer)
    InherentImpact = Column(Integer)
    InherentRiskLevel = Column(Integer)
    CurrentProbability = Column(Integer)
    CurrentImpact = Column(Integer)
    CurrentRiskLevel = Column(Integer)
    ResidualProbability = Column(Integer)
    ResidualImpact = Column(Integer)
    ResidualRiskLevel = Column(Integer)
    TreatmentStrategy = Column(Text)      # accept | avoid | transfer | mitigate
    TreatmentPlan = Column(Text)
    Justification = Column(Text)
    Status = Column(Text)                 # open | assessed | in_treatment | monitored | closed
    IdentifiedDate = Column(Text)
    ReviewDate = Column(Text)
    TargetDate = Column(Text)
    ClosedDate = Column(Text)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKREGISTERENTRY {self.RiskRegisterEntryID}>'


class RISKREGISTERENTRYASSET(ComplianceBase):
    __tablename__ = 'RISKREGISTERENTRYASSET'
    __bind_key__ = 'XCOMPLIANCE'

    RiskRegisterEntryAssetID = Column(Integer, primary_key=True)
    RiskRegisterEntryID = Column(Integer)
    AssetID = Column(Integer)             # ASSET reference (XORCISM database)
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKREGISTERENTRYASSET {self.RiskRegisterEntryAssetID}>'


class RISKREGISTERENTRYCONTROL(ComplianceBase):
    __tablename__ = 'RISKREGISTERENTRYCONTROL'
    __bind_key__ = 'XCOMPLIANCE'

    RiskRegisterEntryControlID = Column(Integer, primary_key=True)
    RiskRegisterEntryID = Column(Integer)
    AppliedControlID = Column(Integer)    # APPLIEDCONTROL reference
    CreatedDate = Column(Text)
    TenantID = Column(Integer)

    def __repr__(self):
        return f'<RISKREGISTERENTRYCONTROL {self.RiskRegisterEntryControlID}>'
