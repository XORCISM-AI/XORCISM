"""
SQLAlchemy models for the XID database (user management, RBAC/CRUD, sessions, audit).
The real schema is created/maintained by the TypeScript server (server/xid.ts).
These models ensure parity on the Python side.
"""
from sqlalchemy import Column, Integer, Text
from .base import Base


class XUSER(Base):
    __tablename__ = 'XUSER'
    __bind_key__ = 'XID'

    UserID = Column(Integer, primary_key=True, autoincrement=True)
    Email = Column(Text, nullable=False)
    LoweredEmail = Column(Text, nullable=False, unique=True)
    DisplayName = Column(Text)
    PasswordHash = Column(Text, nullable=False)
    IsApproved = Column(Integer, default=1)
    IsLockedOut = Column(Integer, default=0)
    MustChangePassword = Column(Integer, default=0)
    FailedPasswordAttemptCount = Column(Integer, default=0)
    FailedPasswordWindowStart = Column(Text)
    LastLoginDate = Column(Text)
    LastPasswordChangedDate = Column(Text)
    CreatedDate = Column(Text)
    CreatedByUserID = Column(Integer)
    Comment = Column(Text)

    def __repr__(self):
        return f'<XUSER {self.Email}>'


class XROLE(Base):
    __tablename__ = 'XROLE'
    __bind_key__ = 'XID'

    RoleID = Column(Integer, primary_key=True, autoincrement=True)
    RoleName = Column(Text, nullable=False, unique=True)
    RoleDescription = Column(Text)
    CreatedDate = Column(Text)

    def __repr__(self):
        return f'<XROLE {self.RoleName}>'


class XUSERROLE(Base):
    __tablename__ = 'XUSERROLE'
    __bind_key__ = 'XID'

    UserRoleID = Column(Integer, primary_key=True, autoincrement=True)
    UserID = Column(Integer, nullable=False)
    RoleID = Column(Integer, nullable=False)

    def __repr__(self):
        return f'<XUSERROLE u={self.UserID} r={self.RoleID}>'


class XPERMISSION(Base):
    __tablename__ = 'XPERMISSION'
    __bind_key__ = 'XID'

    PermissionID = Column(Integer, primary_key=True, autoincrement=True)
    RoleID = Column(Integer, nullable=False)
    ResourceType = Column(Text, nullable=False)   # page | database | table | field
    ResourceKey = Column(Text, nullable=False)
    CanCreate = Column(Integer, default=0)
    CanRead = Column(Integer, default=0)
    CanUpdate = Column(Integer, default=0)
    CanDelete = Column(Integer, default=0)
    CreatedDate = Column(Text)

    def __repr__(self):
        return f'<XPERMISSION {self.ResourceType}:{self.ResourceKey}>'


class XSESSION(Base):
    __tablename__ = 'XSESSION'
    __bind_key__ = 'XID'

    SessionID = Column(Text, primary_key=True)
    UserID = Column(Integer, nullable=False)
    CreatedDate = Column(Text, nullable=False)
    ExpiresDate = Column(Text, nullable=False)
    LastSeenDate = Column(Text)
    IP = Column(Text)
    UserAgent = Column(Text)

    def __repr__(self):
        return f'<XSESSION {self.SessionID[:8]}…>'


class XAUDITLOG(Base):
    __tablename__ = 'XAUDITLOG'
    __bind_key__ = 'XID'

    AuditID = Column(Integer, primary_key=True, autoincrement=True)
    UserID = Column(Integer)
    Action = Column(Text, nullable=False)
    ResourceType = Column(Text)
    ResourceKey = Column(Text)
    Detail = Column(Text)
    IP = Column(Text)
    Timestamp = Column(Text, nullable=False)

    def __repr__(self):
        return f'<XAUDITLOG {self.Action}>'
