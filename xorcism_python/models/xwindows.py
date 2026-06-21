"""
SQLAlchemy models for XWINDOWS database
Auto-generated from SQLite schema - replaces XORCISMModel/XWINDOWS C# POCO classes
"""
from sqlalchemy import Column, Integer, Float, String, Text, LargeBinary, Boolean
from .base import Base


class WINDOWSCOMPUTERACCOUNT(Base):
    __tablename__ = 'WINDOWSCOMPUTERACCOUNT'
    __bind_key__  = 'XWINDOWS'

    WindowsComputerAccountID = Column(Integer, primary_key=True)
    AccountID = Column(Integer)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<WINDOWSCOMPUTERACCOUNT {self.WindowsComputerAccountID}>'

class WINDOWSCRITICALSECTION(Base):
    __tablename__ = 'WINDOWSCRITICALSECTION'
    __bind_key__  = 'XWINDOWS'

    WindowsCriticalSectionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSCRITICALSECTION {self.WindowsCriticalSectionID}>'

class WINDOWSDRIVER(Base):
    __tablename__ = 'WINDOWSDRIVER'
    __bind_key__  = 'XWINDOWS'

    WindowsDriverID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSDRIVER {self.WindowsDriverID}>'

class WINDOWSDRIVETYPE(Base):
    __tablename__ = 'WINDOWSDRIVETYPE'
    __bind_key__  = 'XWINDOWS'

    WindowsDriveTypeID = Column(Integer, primary_key=True)
    WindowsDriveTypeName = Column(Text, nullable=False)
    WindowsDriveTypeDescription = Column(Text)
    VocabularyID = Column(Integer)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<WINDOWSDRIVETYPE {self.WindowsDriveTypeID}>'

class WINDOWSEVENT(Base):
    __tablename__ = 'WINDOWSEVENT'
    __bind_key__  = 'XWINDOWS'

    WindowsEventID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSEVENT {self.WindowsEventID}>'

class WINDOWSEVENTLOG(Base):
    __tablename__ = 'WINDOWSEVENTLOG'
    __bind_key__  = 'XWINDOWS'

    WindowsEventLogID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSEVENTLOG {self.WindowsEventLogID}>'

class WINDOWSEXECUTABLEFILE(Base):
    __tablename__ = 'WINDOWSEXECUTABLEFILE'
    __bind_key__  = 'XWINDOWS'

    WindowsExecutableFileID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSEXECUTABLEFILE {self.WindowsExecutableFileID}>'

class WINDOWSFILE(Base):
    __tablename__ = 'WINDOWSFILE'
    __bind_key__  = 'XWINDOWS'

    WindowsFileID = Column(Integer, primary_key=True)
    WindowsFileGUID = Column(Text)
    FileID = Column(Integer)
    isEncrypted = Column(Integer)
    suspected_malicious = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<WINDOWSFILE {self.WindowsFileID}>'

class WINDOWSGROUP(Base):
    __tablename__ = 'WINDOWSGROUP'
    __bind_key__  = 'XWINDOWS'

    WindowsGroupID = Column(Integer, primary_key=True)
    WindowsGroupName = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<WINDOWSGROUP {self.WindowsGroupID}>'

class WINDOWSGROUPFORWINDOWSUSERACCOUNT(Base):
    __tablename__ = 'WINDOWSGROUPFORWINDOWSUSERACCOUNT'
    __bind_key__  = 'XWINDOWS'

    WindowsGroupWindowsUserAccountID = Column(Integer, primary_key=True)
    WindowsGroupID = Column(Integer, nullable=False)
    WindowsUserAccountID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<WINDOWSGROUPFORWINDOWSUSERACCOUNT {self.WindowsGroupWindowsUserAccountID}>'

class WINDOWSHANDLE(Base):
    __tablename__ = 'WINDOWSHANDLE'
    __bind_key__  = 'XWINDOWS'

    WindowsHandleID = Column(Integer, primary_key=True)
    WindowsHandleObjectID = Column(Integer)
    WindowsHandleName = Column(Text)
    HandleTypeID = Column(Integer)
    Object_Address = Column(Integer)
    Access_Mask = Column(Integer)
    Pointer_Count = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSHANDLE {self.WindowsHandleID}>'

class WINDOWSHANDLELIST(Base):
    __tablename__ = 'WINDOWSHANDLELIST'
    __bind_key__  = 'XWINDOWS'

    WindowsHandleListID = Column(Integer, primary_key=True)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSHANDLELIST {self.WindowsHandleListID}>'

class WINDOWSHANDLELISTHANDLES(Base):
    __tablename__ = 'WINDOWSHANDLELISTHANDLES'
    __bind_key__  = 'XWINDOWS'

    WindowsHandleListHandlesID = Column(Integer, primary_key=True)
    WindowsHandleListID = Column(Integer, nullable=False)
    WindowsHandleID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSHANDLELISTHANDLES {self.WindowsHandleListHandlesID}>'

class WINDOWSHANDLETYPE(Base):
    __tablename__ = 'WINDOWSHANDLETYPE'
    __bind_key__  = 'XWINDOWS'

    WindowsHandleTypeID = Column(Integer, primary_key=True)
    HandleTypeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSHANDLETYPE {self.WindowsHandleTypeID}>'

class WINDOWSKERNELHOOK(Base):
    __tablename__ = 'WINDOWSKERNELHOOK'
    __bind_key__  = 'XWINDOWS'

    WindowsKernelHookID = Column(Integer, primary_key=True)
    Digital_Signature_Hooking = Column(Text)
    DigitalSignatureInfoHookingID = Column(Integer)
    Digital_Signature_Hooked = Column(Text)
    DigitalSignatureInfoHookedID = Column(Integer)
    Hooking_Address = Column(Integer)
    Hook_Description = Column(Text)
    Hooked_Function = Column(Text)
    FunctionHookedID = Column(Integer)
    Hooked_Module = Column(Text)
    ModuleHookedID = Column(Integer)
    Hooking_Module = Column(Text)
    KernelHookID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    DetectionMethodID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSKERNELHOOK {self.WindowsKernelHookID}>'

class WINDOWSKERNELOBJECT(Base):
    __tablename__ = 'WINDOWSKERNELOBJECT'
    __bind_key__  = 'XWINDOWS'

    WindowsKernelObjectID = Column(Integer, primary_key=True)
    IDTEntryListID = Column(Integer)
    SSDTEntryListID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    CollectionMethodID = Column(Integer)
    CollectionToolID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSKERNELOBJECT {self.WindowsKernelObjectID}>'

class WINDOWSMAILSLOT(Base):
    __tablename__ = 'WINDOWSMAILSLOT'
    __bind_key__  = 'XWINDOWS'

    WindowsMailslotID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSMAILSLOT {self.WindowsMailslotID}>'

class WINDOWSMEMORYPAGEREGION(Base):
    __tablename__ = 'WINDOWSMEMORYPAGEREGION'
    __bind_key__  = 'XWINDOWS'

    WindowsMemoryPageRegionID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSMEMORYPAGEREGION {self.WindowsMemoryPageRegionID}>'

class WINDOWSMUTEX(Base):
    __tablename__ = 'WINDOWSMUTEX'
    __bind_key__  = 'XWINDOWS'

    WindowsMutexID = Column(Integer, primary_key=True)
    WindowsHandleID = Column(Integer)
    MutexID = Column(Integer)
    Security_Attributes = Column(Text)
    WindowsMutexDescription = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    VocabularyID = Column(Integer)
    ConfidenceLevelID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSMUTEX {self.WindowsMutexID}>'

class WINDOWSMUTEXHANDLE(Base):
    __tablename__ = 'WINDOWSMUTEXHANDLE'
    __bind_key__  = 'XWINDOWS'

    WindowsMutexHandleID = Column(Integer, primary_key=True)
    WindowsMutexID = Column(Integer, nullable=False)
    WindowsHandleID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSMUTEXHANDLE {self.WindowsMutexHandleID}>'

class WINDOWSMUTEXSECURITYATTRIBUTE(Base):
    __tablename__ = 'WINDOWSMUTEXSECURITYATTRIBUTE'
    __bind_key__  = 'XWINDOWS'

    WindowsMutexSecurityAttributeID = Column(Integer, primary_key=True)
    WindowsMutexID = Column(Integer, nullable=False)
    SecurityAttributeID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSMUTEXSECURITYATTRIBUTE {self.WindowsMutexSecurityAttributeID}>'

class WINDOWSNETWORKROUTEENTRY(Base):
    __tablename__ = 'WINDOWSNETWORKROUTEENTRY'
    __bind_key__  = 'XWINDOWS'

    WindowsNetworkRouteEntryID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSNETWORKROUTEENTRY {self.WindowsNetworkRouteEntryID}>'

class WINDOWSNETWORKSHARE(Base):
    __tablename__ = 'WINDOWSNETWORKSHARE'
    __bind_key__  = 'XWINDOWS'

    WindowsNetworkShareID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSNETWORKSHARE {self.WindowsNetworkShareID}>'

class WINDOWSPIPEOBJECT(Base):
    __tablename__ = 'WINDOWSPIPEOBJECT'
    __bind_key__  = 'XWINDOWS'

    WindowsPipeObjectID = Column(Integer, primary_key=True)
    PipeObjectID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSPIPEOBJECT {self.WindowsPipeObjectID}>'

class WINDOWSPREFETCHACCESSEDFILELIST(Base):
    __tablename__ = 'WINDOWSPREFETCHACCESSEDFILELIST'
    __bind_key__  = 'XWINDOWS'

    WindowsPrefetchObjectAccessedFileListID = Column(Integer, primary_key=True)
    WindowsPrefetchObjectID = Column(Integer, nullable=False)
    AccessedFileListID = Column(Integer, nullable=False)
    BLOB = Column(Text)

    def __repr__(self):
        return f'<WINDOWSPREFETCHACCESSEDFILELIST {self.WindowsPrefetchObjectAccessedFileListID}>'

class WINDOWSPREFETCHCHANGERECORD(Base):
    __tablename__ = 'WINDOWSPREFETCHCHANGERECORD'
    __bind_key__  = 'XWINDOWS'

    WindowsPrefetchChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSPREFETCHCHANGERECORD {self.WindowsPrefetchChangeRecordID}>'

class WINDOWSPREFETCHOBJECT(Base):
    __tablename__ = 'WINDOWSPREFETCHOBJECT'
    __bind_key__  = 'XWINDOWS'

    WindowsPrefetchObjectID = Column(Integer, primary_key=True)
    Application_File_Name = Column(Text)
    FileID = Column(Integer)
    CPEName = Column(Text)
    Prefetch_Hash = Column(Text)
    Times_Executed = Column(Integer)
    First_Run = Column(Text)
    Last_Run = Column(Text)
    VolumeObjectID = Column(Integer)
    WindowsVolumeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSPREFETCHOBJECT {self.WindowsPrefetchObjectID}>'

class WINDOWSPRIVILEGE(Base):
    __tablename__ = 'WINDOWSPRIVILEGE'
    __bind_key__  = 'XWINDOWS'

    WindowsPrivilegeID = Column(Integer, primary_key=True)
    PrivilegeID = Column(Integer)
    User_Right = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)
    VocabularyID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSPRIVILEGE {self.WindowsPrivilegeID}>'

class WINDOWSPROCESS(Base):
    __tablename__ = 'WINDOWSPROCESS'
    __bind_key__  = 'XWINDOWS'

    WindowsProcessID = Column(Integer, primary_key=True)
    ProcessID = Column(Integer)
    WindowsProcessGUID = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    aslr_enabled = Column(Integer)
    dep_enabled = Column(Integer)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<WINDOWSPROCESS {self.WindowsProcessID}>'

class WINDOWSPROCESSTOKEN(Base):
    __tablename__ = 'WINDOWSPROCESSTOKEN'
    __bind_key__  = 'XWINDOWS'

    WindowsProcessTokenID = Column(Integer, primary_key=True)
    WindowsProcessID = Column(Integer, nullable=False)
    TokenID = Column(Integer, nullable=False)
    IntegrityLevelID = Column(Integer)
    ConfidenceLevelID = Column(Integer)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<WINDOWSPROCESSTOKEN {self.WindowsProcessTokenID}>'

class WINDOWSREGISTRYKEYOBJECT(Base):
    __tablename__ = 'WINDOWSREGISTRYKEYOBJECT'
    __bind_key__  = 'XWINDOWS'

    WindowsRegistryKeyObjectID = Column(Integer, primary_key=True)
    Hive = Column(Text)
    operation = Column(Text)
    Full_Key = Column(Text)
    RegistryHiveID = Column(Integer)
    Number_Values = Column(Integer)
    Name = Column(Text)
    comment = Column(Text)
    RegistryValuesID = Column(Integer)
    Modified_Time = Column(Text)
    Creator_Username = Column(Text)
    AccountID = Column(Integer)
    UserAccountID = Column(Integer)
    WindowsUserAccountID = Column(Integer)
    WindowsHandleListID = Column(Integer)
    Number_Subkeys = Column(Integer)
    RegistrySubkeysID = Column(Integer)
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
        return f'<WINDOWSREGISTRYKEYOBJECT {self.WindowsRegistryKeyObjectID}>'

class WINDOWSSEMAPHORE(Base):
    __tablename__ = 'WINDOWSSEMAPHORE'
    __bind_key__  = 'XWINDOWS'

    WindowsSemaphoreID = Column(Integer, primary_key=True)
    SemaphoreID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSSEMAPHORE {self.WindowsSemaphoreID}>'

class WINDOWSSERVICE(Base):
    __tablename__ = 'WINDOWSSERVICE'
    __bind_key__  = 'XWINDOWS'

    WindowsServiceID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSSERVICE {self.WindowsServiceID}>'

class WINDOWSSYSTEM(Base):
    __tablename__ = 'WINDOWSSYSTEM'
    __bind_key__  = 'XWINDOWS'

    WindowsSystemID = Column(Integer, primary_key=True)
    SystemID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSSYSTEM {self.WindowsSystemID}>'

class WINDOWSSYSTEMRESTORE(Base):
    __tablename__ = 'WINDOWSSYSTEMRESTORE'
    __bind_key__  = 'XWINDOWS'

    WindowsSystemRestoreID = Column(Integer, primary_key=True)
    Restore_Point_Description = Column(Text)
    Restore_Point_Full_Path = Column(Text)
    Restore_Point_Name = Column(Text)
    Restore_Point_Type = Column(Text)
    ACL_Change_SID = Column(Text)
    ACL_Change_Username = Column(Text)
    Backup_File_Name = Column(Text)
    Change_Event = Column(Text)
    ChangeLog_Entry_Flags = Column(Text)
    ChangeLog_Entry_Sequence_Number = Column(Integer)
    ChangeLog_Entry_Type = Column(Text)
    Change_Log_File_Name = Column(Text)
    Created = Column(Text)
    File_Attributes = Column(Text)
    New_File_Name = Column(Text)
    Original_File_Name = Column(Text)
    Original_Short_File_Name = Column(Text)
    Process_Name = Column(Text)
    Registry_Hive_List = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSSYSTEMRESTORE {self.WindowsSystemRestoreID}>'

class WINDOWSTASK(Base):
    __tablename__ = 'WINDOWSTASK'
    __bind_key__  = 'XWINDOWS'

    WindowsTaskID = Column(Integer, primary_key=True)
    TaskID = Column(Integer)
    SessionCronID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    Status = Column(Text)
    TaskStatusID = Column(Integer)
    Priority = Column(Text)
    TaskPriorityID = Column(Integer)
    Name = Column(Text)
    Application_Name = Column(Text)
    ApplicationID = Column(Integer)
    CPEName = Column(Text)
    Parameters = Column(Text)
    Flags = Column(Text)
    Account_Name = Column(Text)
    AccountID = Column(Integer)
    Account_Run_Level = Column(Text)
    Account_Logon_Type = Column(Text)
    Creator = Column(Text)
    Creation_Date = Column(Text)
    Most_Recent_Run_Time = Column(Text)
    Exit_Code = Column(Integer)
    Max_Run_Time = Column(Integer)
    Next_Run_Time = Column(Text)
    Comment = Column(Text)
    Working_Directory = Column(Text)
    DirectoryID = Column(Integer)
    Work_Item_Data = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSTASK {self.WindowsTaskID}>'

class WINDOWSTHREAD(Base):
    __tablename__ = 'WINDOWSTHREAD'
    __bind_key__  = 'XWINDOWS'

    WindowsThreadID = Column(Integer, primary_key=True)
    Thread_ID = Column(Integer)
    WindowsHandleID = Column(Integer)
    ThreadRunningStatusID = Column(Integer)
    Running_Status = Column(Text)
    Context = Column(Text)
    Priority = Column(Integer)
    Creation_Flags = Column(Text)
    Creation_Time = Column(Text)
    Start_Address = Column(Text)
    StartMemoryAddressID = Column(Integer)
    Parameter_Address = Column(Text)
    ParameterMemoryAddressID = Column(Integer)
    Security_Attributes = Column(Text)
    Stack_Size = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSTHREAD {self.WindowsThreadID}>'

class WINDOWSUSERACCOUNT(Base):
    __tablename__ = 'WINDOWSUSERACCOUNT'
    __bind_key__  = 'XWINDOWS'

    WindowsUserAccountID = Column(Integer, primary_key=True)
    WindowsUserAccountGUID = Column(Text)
    AccountID = Column(Integer)
    UserAccountID = Column(Integer)
    WindowsComputerAccountID = Column(Integer)
    Security_ID = Column(Text)
    Security_Type = Column(Text)
    CreatedDate = Column(Text)
    CreationObjectID = Column(Integer)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    TrustLevelID = Column(Integer)
    TrustReasonID = Column(Integer)
    isEncrypted = Column(Integer)
    suspected_malicious = Column(Integer)
    SuspectedMaliciousReasonID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSUSERACCOUNT {self.WindowsUserAccountID}>'

class WINDOWSUSERACCOUNTCHANGERECORD(Base):
    __tablename__ = 'WINDOWSUSERACCOUNTCHANGERECORD'
    __bind_key__  = 'XWINDOWS'

    WindowsUserAccountChangeRecordID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSUSERACCOUNTCHANGERECORD {self.WindowsUserAccountChangeRecordID}>'

class WINDOWSUSERACCOUNTPRIVILEGE(Base):
    __tablename__ = 'WINDOWSUSERACCOUNTPRIVILEGE'
    __bind_key__  = 'XWINDOWS'

    WindowsUserAccountPrivilegeID = Column(Integer, primary_key=True)
    WindowsUserAccountID = Column(Integer, nullable=False)
    WindowsPrivilegeID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSUSERACCOUNTPRIVILEGE {self.WindowsUserAccountPrivilegeID}>'

class WINDOWSVOLUME(Base):
    __tablename__ = 'WINDOWSVOLUME'
    __bind_key__  = 'XWINDOWS'

    WindowsVolumeID = Column(Integer, primary_key=True)
    WindowsVolumeGUID = Column(Text)
    VolumeObjectID = Column(Integer)
    Drive_Letter = Column(Text)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSVOLUME {self.WindowsVolumeID}>'

class WINDOWSVOLUMEATTRIBUTE(Base):
    __tablename__ = 'WINDOWSVOLUMEATTRIBUTE'
    __bind_key__  = 'XWINDOWS'

    WindowsVolumeAttributeID = Column(Integer, primary_key=True)
    AttributeID = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSVOLUMEATTRIBUTE {self.WindowsVolumeAttributeID}>'

class WINDOWSVOLUMEATTRIBUTEENUM(Base):
    __tablename__ = 'WINDOWSVOLUMEATTRIBUTEENUM'
    __bind_key__  = 'XWINDOWS'

    WindowsVolumeAttributeEnumID = Column(Integer, primary_key=True)
    WindowsVolumeAttributeEnumValue = Column(Text, nullable=False)
    WindowsVolumeAttributeEnumDescription = Column(Text)
    VocabularyID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    isEncrypted = Column(Integer)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)

    def __repr__(self):
        return f'<WINDOWSVOLUMEATTRIBUTEENUM {self.WindowsVolumeAttributeEnumID}>'

class WINDOWSVOLUMEATTRIBUTESLIST(Base):
    __tablename__ = 'WINDOWSVOLUMEATTRIBUTESLIST'
    __bind_key__  = 'XWINDOWS'

    WindowsVolumeAttributesListID = Column(Integer, primary_key=True)
    WindowsVolumeID = Column(Integer, nullable=False)
    WindowsVolumeAttributeID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSVOLUMEATTRIBUTESLIST {self.WindowsVolumeAttributesListID}>'

class WINDOWSVOLUMEENCRYPTION(Base):
    __tablename__ = 'WINDOWSVOLUMEENCRYPTION'
    __bind_key__  = 'XWINDOWS'

    WindowsVolumeEncryptionID = Column(Integer, primary_key=True)
    WindowsVolumeID = Column(Integer, nullable=False)
    EncryptionID = Column(Integer, nullable=False)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    ConfidenceLevelID = Column(Integer)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSVOLUMEENCRYPTION {self.WindowsVolumeEncryptionID}>'

class WINDOWSWAITABLETIMER(Base):
    __tablename__ = 'WINDOWSWAITABLETIMER'
    __bind_key__  = 'XWINDOWS'

    WindowsWaitableTimerID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINDOWSWAITABLETIMER {self.WindowsWaitableTimerID}>'

class WINDOWSWAITABLETIMEROBJECT(Base):
    __tablename__ = 'WINDOWSWAITABLETIMEROBJECT'
    __bind_key__  = 'XWINDOWS'

    WindowsWaitableTimerObjectID = Column(Integer, primary_key=True)
    WindowsHandleID = Column(Integer)
    WindowsWaitableTimerObjectName = Column(Text)
    Security_Attributes = Column(Text)
    WaitableTimerTypeID = Column(Integer)
    CreatedDate = Column(Text)
    BLOB = Column(Text)
    ValidFromDate = Column(Text)
    ValidUntilDate = Column(Text)
    isEncrypted = Column(Integer)

    def __repr__(self):
        return f'<WINDOWSWAITABLETIMEROBJECT {self.WindowsWaitableTimerObjectID}>'

class WINWAITABLETIMER(Base):
    __tablename__ = 'WINWAITABLETIMER'
    __bind_key__  = 'XWINDOWS'

    WinWaitableTimerID = Column(Integer, primary_key=True)

    def __repr__(self):
        return f'<WINWAITABLETIMER {self.WinWaitableTimerID}>'
