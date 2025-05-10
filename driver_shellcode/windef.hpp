#pragma once
#include <stdint.h>

#define FALSE 0
#define TRUE 1

#define STATUS_SUCCESS 0

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1       // winnt
#endif

typedef long LONG;
typedef unsigned long ULONG;
typedef const short CSHORT;
typedef unsigned short USHORT;
typedef void* PVOID;
typedef uint64_t ULONG_PTR;
typedef const char CCHAR;
typedef unsigned char UCHAR;
typedef UCHAR BOOLEAN;
typedef char CHAR;
typedef __int64 LONGLONG;
typedef const char* PCSTR;
typedef uint8_t BYTE;
typedef unsigned long DWORD;
typedef unsigned long long ULONG64;
typedef wchar_t WCHAR;

typedef LONG NTSTATUS;
typedef CCHAR KPROCESSOR_MODE;
typedef UCHAR KIRQL;
typedef ULONG ACCESS_MASK;
typedef ULONG_PTR SIZE_T, * PSIZE_T;
typedef LONG KPRIORITY;

#ifdef __has_builtin
#if __has_builtin(__builtin_offsetof)
#define FIELD_OFFSET(type, field)    ((LONG)__builtin_offsetof(type, field))
#define UFIELD_OFFSET(type, field)    ((ULONG)__builtin_offsetof(type, field))
#endif
#endif

typedef struct _DEVICE_OBJECT* PDEVICE_OBJECT;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) wchar_t*   Buffer;

} UNICODE_STRING, *PUNICODE_STRING;

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        ULONG LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };

    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef struct _KDEVICE_QUEUE_ENTRY {
    LIST_ENTRY DeviceListEntry;
    ULONG SortKey;
    BOOLEAN Inserted;
} KDEVICE_QUEUE_ENTRY, * PKDEVICE_QUEUE_ENTRY, * PRKDEVICE_QUEUE_ENTRY;

typedef struct _KAPC {
    UCHAR Type;
    UCHAR SpareByte0;
    UCHAR Size;
    UCHAR SpareByte1;
    ULONG SpareLong0;
    struct _KTHREAD* Thread;
    LIST_ENTRY ApcListEntry;
    PVOID Reserved[3];
    PVOID NormalContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    CCHAR ApcStateIndex;
    KPROCESSOR_MODE ApcMode;
    BOOLEAN Inserted;
} KAPC, * PKAPC, * PRKAPC;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55

        //
        //  These are special versions of these operations (defined earlier)
        //  which can be used by kernel mode drivers only to bypass security
        //  access checks for Rename and HardLink operations.  These operations
        //  are only recognized by the IOManager, a file system should never
        //  receive these.
        //

        FileRenameInformationBypassAccessCheck,         // 56
        FileLinkInformationBypassAccessCheck,           // 57

            //
            // End of special information classes reserved for IOManager.
            //

            FileVolumeNameInformation,                      // 58
            FileIdInformation,                              // 59
            FileIdExtdDirectoryInformation,                 // 60
            FileReplaceCompletionInformation,               // 61
            FileHardLinkFullIdInformation,                  // 62
            FileIdExtdBothDirectoryInformation,             // 63
            FileDispositionInformationEx,                   // 64
            FileRenameInformationEx,                        // 65
            FileRenameInformationExBypassAccessCheck,       // 66
            FileDesiredStorageClassInformation,             // 67
            FileStatInformation,                            // 68
            FileMemoryPartitionInformation,                 // 69
            FileStatLxInformation,                          // 70
            FileCaseSensitiveInformation,                   // 71
            FileLinkInformationEx,                          // 72
            FileLinkInformationExBypassAccessCheck,         // 73
            FileStorageReserveIdInformation,                // 74
            FileCaseSensitiveInformationForceAccessCheck,   // 75
            FileKnownFolderInformation,                     // 76

            FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS {
    DirectoryNotifyInformation = 1,
    DirectoryNotifyExtendedInformation // 2
} DIRECTORY_NOTIFY_INFORMATION_CLASS, * PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _FSINFOCLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,         // 2
    FileFsSizeInformation,          // 3
    FileFsDeviceInformation,        // 4
    FileFsAttributeInformation,     // 5
    FileFsControlInformation,       // 6
    FileFsFullSizeInformation,      // 7
    FileFsObjectIdInformation,      // 8
    FileFsDriverPathInformation,    // 9
    FileFsVolumeFlagsInformation,   // 10
    FileFsSectorSizeInformation,    // 11
    FileFsDataCopyInformation,      // 12
    FileFsMetadataSizeInformation,  // 13
    FileFsFullSizeInformationEx,    // 14
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, * PFS_INFORMATION_CLASS;

typedef ULONG LCID;
typedef ULONG SECURITY_INFORMATION, * PSECURITY_INFORMATION;

typedef enum _DEVICE_RELATION_TYPE {
    BusRelations,
    EjectionRelations,
    PowerRelations,
    RemovalRelations,
    TargetDeviceRelation,
    SingleBusRelations,
    TransportRelations
} DEVICE_RELATION_TYPE, * PDEVICE_RELATION_TYPE;

typedef enum {
    BusQueryDeviceID = 0,       // <Enumerator>\<Enumerator-specific device id>
    BusQueryHardwareIDs = 1,    // Hardware ids
    BusQueryCompatibleIDs = 2,  // compatible device ids
    BusQueryInstanceID = 3,     // persistent id for this instance of the device
    BusQueryDeviceSerialNumber = 4,   // serial number for this device
    BusQueryContainerID = 5     // unique id of the device's physical container
} BUS_QUERY_ID_TYPE, * PBUS_QUERY_ID_TYPE;

typedef enum {
    DeviceTextDescription = 0,            // DeviceDesc property
    DeviceTextLocationInformation = 1     // DeviceLocation property
} DEVICE_TEXT_TYPE, * PDEVICE_TEXT_TYPE;

typedef enum {
    PowerActionNone = 0,
    PowerActionReserved,
    PowerActionSleep,
    PowerActionHibernate,
    PowerActionShutdown,
    PowerActionShutdownReset,
    PowerActionShutdownOff,
    PowerActionWarmEject,
    PowerActionDisplayOff
} POWER_ACTION, * PPOWER_ACTION;

typedef enum _DEVICE_POWER_STATE {
    PowerDeviceUnspecified = 0,
    PowerDeviceD0,
    PowerDeviceD1,
    PowerDeviceD2,
    PowerDeviceD3,
    PowerDeviceMaximum
} DEVICE_POWER_STATE, * PDEVICE_POWER_STATE;

typedef enum _SYSTEM_POWER_STATE {
    PowerSystemUnspecified = 0,
    PowerSystemWorking = 1,
    PowerSystemSleeping1 = 2,
    PowerSystemSleeping2 = 3,
    PowerSystemSleeping3 = 4,
    PowerSystemHibernate = 5,
    PowerSystemShutdown = 6,
    PowerSystemMaximum = 7
} SYSTEM_POWER_STATE, * PSYSTEM_POWER_STATE;

typedef union _POWER_STATE {
    SYSTEM_POWER_STATE SystemState;
    DEVICE_POWER_STATE DeviceState;
} POWER_STATE, * PPOWER_STATE;

typedef enum _POWER_STATE_TYPE {
    SystemPowerState = 0,
    DevicePowerState
} POWER_STATE_TYPE, * PPOWER_STATE_TYPE;

typedef enum _DEVICE_USAGE_NOTIFICATION_TYPE {
    DeviceUsageTypeUndefined,
    DeviceUsageTypePaging,
    DeviceUsageTypeHibernation,
    DeviceUsageTypeDumpFile,
    DeviceUsageTypeBoot,
    DeviceUsageTypePostDisplay,
    DeviceUsageTypeGuestAssigned
} DEVICE_USAGE_NOTIFICATION_TYPE;

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;

    //
    // The following user parameters are based on the service that is being
    // invoked.  Drivers and file systems can determine which set to use based
    // on the above major and minor function codes.
    //

    union {

        //
        // System service parameters for:  NtCreateFile
        //

        struct {
            PVOID SecurityContext;
            ULONG Options;
            USHORT FileAttributes __attribute__((aligned(8)));
            USHORT ShareAccess;
            ULONG EaLength __attribute__((aligned(8)));
        } Create;

        //
        // System service parameters for:  NtCreateNamedPipeFile
        //
        // Notice that the fields in the following parameter structure must
        // match those for the create structure other than the last longword.
        // This is so that no distinctions need be made by the I/O system's
        // parse routine other than for the last longword.
        //

        struct {
            PVOID SecurityContext;
            ULONG Options;
            USHORT Reserved __attribute__((aligned(8)));
            USHORT ShareAccess;
            PVOID Parameters;
        } CreatePipe;

        //
        // System service parameters for:  NtCreateMailslotFile
        //
        // Notice that the fields in the following parameter structure must
        // match those for the create structure other than the last longword.
        // This is so that no distinctions need be made by the I/O system's
        // parse routine other than for the last longword.
        //

        struct {
            PVOID SecurityContext;
            ULONG Options;
            USHORT Reserved __attribute__((aligned(8)));
            USHORT ShareAccess;
            PVOID Parameters;
        } CreateMailslot;

        //
        // System service parameters for:  NtReadFile
        //

        struct {
            ULONG Length;
            ULONG Key __attribute__((aligned(8)));
            ULONG Flags;
            LARGE_INTEGER ByteOffset;
        } Read;

        //
        // System service parameters for:  NtWriteFile
        //

        struct {
            ULONG Length;
            ULONG Key __attribute__((aligned(8)));
            ULONG Flags;
            LARGE_INTEGER ByteOffset;
        } Write;

        //
        // System service parameters for:  NtQueryDirectoryFile
        //

        struct {
            ULONG Length;
            PUNICODE_STRING FileName;
            FILE_INFORMATION_CLASS FileInformationClass;
            ULONG FileIndex __attribute__((aligned(8)));
        } QueryDirectory;

        //
        // System service parameters for:  NtNotifyChangeDirectoryFile / NtNotifyChangeDirectoryFileEx
        //

        struct {
            ULONG Length;
            ULONG CompletionFilter __attribute__((aligned(8)));
        } NotifyDirectory;

        //
        // System service parameters for:  NtNotifyChangeDirectoryFile / NtNotifyChangeDirectoryFileEx
        //
        // For minor code IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX
        // N.B. Keep Length and CompletionFilter aligned with NotifyDirectory.
        //

        struct {
            ULONG Length;
            ULONG CompletionFilter __attribute__((aligned(8)));
            DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass __attribute__((aligned(8)));
        } NotifyDirectoryEx;

        //
        // System service parameters for:  NtQueryInformationFile
        //

        struct {
            ULONG Length;
            FILE_INFORMATION_CLASS FileInformationClass __attribute__((aligned(8)));
        } QueryFile;

        //
        // System service parameters for:  NtSetInformationFile
        //

        struct {
            ULONG Length;
            FILE_INFORMATION_CLASS FileInformationClass __attribute__((aligned(8)));
            PVOID FileObject;
            union {
                struct {
                    BOOLEAN ReplaceIfExists;
                    BOOLEAN AdvanceOnly;
                };
                ULONG ClusterCount;
                PVOID DeleteHandle;
            };
        } SetFile;



        //
        // System service parameters for:  NtQueryEaFile
        //

        struct {
            ULONG Length;
            PVOID EaList;
            ULONG EaListLength;
            ULONG EaIndex __attribute__((aligned(8)));
        } QueryEa;

        //
        // System service parameters for:  NtSetEaFile
        //

        struct {
            ULONG Length;
        } SetEa;



        //
        // System service parameters for:  NtQueryVolumeInformationFile
        //

        struct {
            ULONG Length;
            FS_INFORMATION_CLASS FsInformationClass __attribute__((aligned(8)));
        } QueryVolume;



        //
        // System service parameters for:  NtSetVolumeInformationFile
        //

        struct {
            ULONG Length;
            FS_INFORMATION_CLASS FsInformationClass __attribute__((aligned(8)));
        } SetVolume;

        //
        // System service parameters for:  NtFsControlFile
        //
        // Note that the user's output buffer is stored in the UserBuffer field
        // and the user's input buffer is stored in the SystemBuffer field.
        //

        struct {
            ULONG OutputBufferLength;
            ULONG InputBufferLength __attribute__((aligned(8)));
            ULONG FsControlCode __attribute__((aligned(8)));
            PVOID Type3InputBuffer;
        } FileSystemControl;
        //
        // System service parameters for:  NtLockFile/NtUnlockFile
        //

        struct {
            PLARGE_INTEGER Length;
            ULONG Key __attribute__((aligned(8)));
            LARGE_INTEGER ByteOffset;
        } LockControl;

        //
        // System service parameters for:  NtFlushBuffersFile
        //
        // No extra user-supplied parameters.
        //



        //
        // System service parameters for:  NtCancelIoFile
        //
        // No extra user-supplied parameters.
        //



        //
        // System service parameters for:  NtDeviceIoControlFile
        //
        // Note that the user's output buffer is stored in the UserBuffer field
        // and the user's input buffer is stored in the SystemBuffer field.
        //

        struct {
            ULONG OutputBufferLength;
            ULONG InputBufferLength __attribute__((aligned(8)));
            ULONG IoControlCode __attribute__((aligned(8)));
            PVOID Type3InputBuffer;
        } DeviceIoControl;

        //
        // System service parameters for:  NtQuerySecurityObject
        //

        struct {
            SECURITY_INFORMATION SecurityInformation;
            ULONG Length __attribute__((aligned(8)));
        } QuerySecurity;

        //
        // System service parameters for:  NtSetSecurityObject
        //

        struct {
            SECURITY_INFORMATION SecurityInformation;
            PVOID SecurityDescriptor;
        } SetSecurity;

        //
        // Non-system service parameters.
        //
        // Parameters for MountVolume
        //

        struct {
            PVOID Vpb;
            PDEVICE_OBJECT DeviceObject;
        } MountVolume;

        //
        // Parameters for VerifyVolume
        //

        struct {
            PVOID Vpb;
            PDEVICE_OBJECT DeviceObject;
        } VerifyVolume;

        //
        // Parameters for Scsi with internal device control.
        //

        struct {
            struct _SCSI_REQUEST_BLOCK* Srb;
        } Scsi;



        //
        // System service parameters for:  NtQueryQuotaInformationFile
        //

        struct {
            ULONG Length;
            PVOID StartSid;
            PVOID SidList;
            ULONG SidListLength;
        } QueryQuota;

        //
        // System service parameters for:  NtSetQuotaInformationFile
        //

        struct {
            ULONG Length;
        } SetQuota;



        //
        // Parameters for IRP_MN_QUERY_DEVICE_RELATIONS
        //

        struct {
            DEVICE_RELATION_TYPE Type;
        } QueryDeviceRelations;

        //
        // Parameters for IRP_MN_QUERY_INTERFACE
        //

        struct {
            PVOID InterfaceType;
            USHORT Size;
            USHORT Version;
            PVOID Interface;
            PVOID InterfaceSpecificData;
        } QueryInterface;

        //
        // Parameters for IRP_MN_QUERY_CAPABILITIES
        //

        struct {
            PVOID Capabilities;
        } DeviceCapabilities;

        //
        // Parameters for IRP_MN_FILTER_RESOURCE_REQUIREMENTS
        //

        struct {
            PVOID IoResourceRequirementList;
        } FilterResourceRequirements;

        //
        // Parameters for IRP_MN_READ_CONFIG and IRP_MN_WRITE_CONFIG
        //

        struct {
            ULONG WhichSpace;
            PVOID Buffer;
            ULONG Offset;
            ULONG Length __attribute__((aligned(8)));
        } ReadWriteConfig;

        //
        // Parameters for IRP_MN_SET_LOCK
        //

        struct {
            BOOLEAN Lock;
        } SetLock;

        //
        // Parameters for IRP_MN_QUERY_ID
        //

        struct {
            BUS_QUERY_ID_TYPE IdType;
        } QueryId;

        //
        // Parameters for IRP_MN_QUERY_DEVICE_TEXT
        //

        struct {
            DEVICE_TEXT_TYPE DeviceTextType;
            LCID LocaleId __attribute__((aligned(8)));
        } QueryDeviceText;

        //
        // Parameters for IRP_MN_DEVICE_USAGE_NOTIFICATION
        //

        struct {
            BOOLEAN InPath;
            BOOLEAN Reserved[3];
            DEVICE_USAGE_NOTIFICATION_TYPE Type __attribute__((aligned(8)));
        } UsageNotification;

        //
        // Parameters for IRP_MN_WAIT_WAKE
        //

        struct {
            SYSTEM_POWER_STATE PowerState;
        } WaitWake;

        //
        // Parameter for IRP_MN_POWER_SEQUENCE
        //

        struct {
            PVOID PowerSequence;
        } PowerSequence;

        //
        // Parameters for IRP_MN_SET_POWER and IRP_MN_QUERY_POWER
        //
        struct {
            ULONG SystemContext;
            POWER_STATE_TYPE Type __attribute__((aligned(8)));
            POWER_STATE State __attribute__((aligned(8)));
            POWER_ACTION ShutdownType __attribute__((aligned(8)));
        } Power;

        //
        // Parameters for StartDevice
        //

        struct {
            PVOID AllocatedResources;
            PVOID AllocatedResourcesTranslated;
        } StartDevice;

        //
        // Parameters for Cleanup
        //
        // No extra parameters supplied
        //

        //
        // WMI Irps
        //

        struct {
            ULONG_PTR ProviderId;
            PVOID DataPath;
            ULONG BufferSize;
            PVOID Buffer;
        } WMI;

        //
        // Others - driver-specific
        //

        struct {
            PVOID Argument1;
            PVOID Argument2;
            PVOID Argument3;
            PVOID Argument4;
        } Others;

    } Parameters;

    //
    // Save a pointer to this device driver's device object for this request
    // so it can be passed to the completion routine if needed.
    //

    PDEVICE_OBJECT DeviceObject;

    //
    // The following location contains a pointer to the file object for this
    // request.
    //

    PVOID FileObject;

    //
    // The following routine is invoked depending on the flags in the above
    // flags field.
    //

    PVOID CompletionRoutine;

    //
    // The following is used to store the address of the context parameter
    // that should be passed to the CompletionRoutine.
    //

    PVOID Context;

} IO_STACK_LOCATION, * PIO_STACK_LOCATION;

//
// I/O Request Packet (IRP) definition
//
typedef struct _IRP {
    CSHORT Type;
    USHORT Size;


    //
    // Define the common fields used to control the IRP.
    //

    //
    // Define a pointer to the Memory Descriptor List (MDL) for this I/O
    // request.  This field is only used if the I/O is "direct I/O".
    //

    PVOID MdlAddress;

    //
    // Flags word - used to remember various flags.
    //

    ULONG Flags;

    //
    // The following union is used for one of three purposes:
    //
    //    1. This IRP is an associated IRP.  The field is a pointer to a master
    //       IRP.
    //
    //    2. This is the master IRP.  The field is the count of the number of
    //       IRPs which must complete (associated IRPs) before the master can
    //       complete.
    //
    //    3. This operation is being buffered and the field is the address of
    //       the system space buffer.
    //

    union {
        struct _IRP* MasterIrp;
        __volatile LONG IrpCount;
        PVOID SystemBuffer;
    } AssociatedIrp;

    //
    // Thread list entry - allows queuing the IRP to the thread pending I/O
    // request packet list.
    //

    LIST_ENTRY ThreadListEntry;

    //
    // I/O status - final status of operation.
    //

    IO_STATUS_BLOCK IoStatus;

    //
    // Requester mode - mode of the original requester of this operation.
    //

    KPROCESSOR_MODE RequestorMode;

    //
    // Pending returned - TRUE if pending was initially returned as the
    // status for this packet.
    //

    BOOLEAN PendingReturned;

    //
    // Stack state information.
    //

    CHAR StackCount;
    CHAR CurrentLocation;

    //
    // Cancel - packet has been canceled.
    //

    BOOLEAN Cancel;

    //
    // Cancel Irql - Irql at which the cancel spinlock was acquired.
    //

    KIRQL CancelIrql;

    //
    // ApcEnvironment - Used to save the APC environment at the time that the
    // packet was initialized.
    //

    CCHAR ApcEnvironment;

    //
    // Allocation control flags.
    //

    UCHAR AllocationFlags;

    //
    // User parameters.
    //

    union {
        PIO_STATUS_BLOCK UserIosb;

        //
        // Context used when the Irp is managed by IoRing and is used by IoRing.
        // UserIosb is used to cancel an Irp, so sharing space with UserIosb
        // let IoRing cancel an Irp based on its context.
        //

        PVOID IoRingContext;
    };

    PVOID UserEvent;
    union {
        struct {
            union {
                PVOID UserApcRoutine;
                PVOID IssuingProcess;
            };
            union {
                PVOID UserApcContext;

                //
                // IoRing object that rolled this Irp, if any.  The completion
                // is processed through this IoRing object.  UserApcRoutine and
                // UserApcContext is not supported when issuing IOs through an
                // IoRing so we union this with UserApcContext.  We did not use
                // UserApcRoutine because IssuingProcess use the same location
                // and is used when an Irp is queued to FileObject and when the
                // Irp is managed by IoRing it is queued to the FileObject.
                //

                struct _IORING_OBJECT* IoRing;
            };
        } AsynchronousParameters;
        LARGE_INTEGER AllocationSize;
    } Overlay;

    //
    // CancelRoutine - Used to contain the address of a cancel routine supplied
    // by a device driver when the IRP is in a cancelable state.
    //

    __volatile PVOID CancelRoutine;

    //
    // Note that the UserBuffer parameter is outside of the stack so that I/O
    // completion can copy data back into the user's address space without
    // having to know exactly which service was being invoked.  The length
    // of the copy is stored in the second half of the I/O status block. If
    // the UserBuffer field is NULL, then no copy is performed.
    //

    PVOID UserBuffer;

    //
    // Kernel structures
    //
    // The following section contains kernel structures which the IRP needs
    // in order to place various work information in kernel controller system
    // queues.  Because the size and alignment cannot be controlled, they are
    // placed here at the end so they just hang off and do not affect the
    // alignment of other fields in the IRP.
    //

    union {

        struct {

            union {

                //
                // DeviceQueueEntry - The device queue entry field is used to
                // queue the IRP to the device driver device queue.
                //

                KDEVICE_QUEUE_ENTRY DeviceQueueEntry;

                struct {

                    //
                    // The following are available to the driver to use in
                    // whatever manner is desired, while the driver owns the
                    // packet.
                    //

                    PVOID DriverContext[4];

                };

            };

            //
            // Thread - pointer to caller's Thread Control Block.
            //

            PVOID Thread;

            //
            // Auxiliary buffer - pointer to any auxiliary buffer that is
            // required to pass information to a driver that is not contained
            // in a normal buffer.
            //

            CHAR* AuxiliaryBuffer;

            //
            // The following unnamed structure must be exactly identical
            // to the unnamed structure used in the minipacket header used
            // for completion queue entries.
            //

            struct {

                //
                // List entry - used to queue the packet to completion queue, among
                // others.
                //

                LIST_ENTRY ListEntry;

                union {

                    //
                    // Current stack location - contains a pointer to the current
                    // IO_STACK_LOCATION structure in the IRP stack.  This field
                    // should never be directly accessed by drivers.  They should
                    // use the standard functions.
                    //

                    struct _IO_STACK_LOCATION* CurrentStackLocation;

                    //
                    // Minipacket type.
                    //

                    ULONG PacketType;
                };
            };

            //
            // Original file object - pointer to the original file object
            // that was used to open the file.  This field is owned by the
            // I/O system and should not be used by any other drivers.
            //

            PVOID OriginalFileObject;

        } Overlay;

        //
        // APC - This APC control block is used for the special kernel APC as
        // well as for the caller's APC, if one was specified in the original
        // argument list.  If so, then the APC is reused for the normal APC for
        // whatever mode the caller was in and the "special" routine that is
        // invoked before the APC gets control simply deallocates the IRP.
        //

        KAPC Apc;

        //
        // CompletionKey - This is the key that is used to distinguish
        // individual I/O operations initiated on a single file handle.
        //

        PVOID CompletionKey;

    } Tail;

} IRP;

typedef IRP* PIRP;

typedef struct _DRIVER_EXTENSION {

    //
    // Back pointer to Driver Object
    //

    struct _DRIVER_OBJECT* DriverObject;

    //
    // The AddDevice entry point is called by the Plug & Play manager
    // to inform the driver when a new device instance arrives that this
    // driver must control.
    //

    PVOID AddDevice;

    //
    // The count field is used to count the number of times the driver has
    // had its registered reinitialization routine invoked.
    //

    ULONG Count;

    //
    // The service name field is used by the pnp manager to determine
    // where the driver related info is stored in the registry.
    //

    UNICODE_STRING ServiceKeyName;

    //
    // Note: any new shared fields get added here.
    //


} DRIVER_EXTENSION, * PDRIVER_EXTENSION;

#define IRP_MJ_MAXIMUM_FUNCTION         0x1b
typedef struct _DRIVER_OBJECT {
    CSHORT Type;
    CSHORT Size;

    //
    // The following links all of the devices created by a single driver
    // together on a list, and the Flags word provides an extensible flag
    // location for driver objects.
    //

    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;

    //
    // The following section describes where the driver is loaded.  The count
    // field is used to count the number of times the driver has had its
    // registered reinitialization routine invoked.
    //

    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PDRIVER_EXTENSION DriverExtension;

    //
    // The driver name field is used by the error log thread
    // determine the name of the driver that an I/O request is/was bound.
    //

    UNICODE_STRING DriverName;

    //
    // The following section is for registry support.  This is a pointer
    // to the path to the hardware information in the registry
    //

    PUNICODE_STRING HardwareDatabase;

    //
    // The following section contains the optional pointer to an array of
    // alternate entry points to a driver for "fast I/O" support.  Fast I/O
    // is performed by invoking the driver routine directly with separate
    // parameters, rather than using the standard IRP call mechanism.  Note
    // that these functions may only be used for synchronous I/O, and when
    // the file is cached.
    //

    PVOID FastIoDispatch;

    //
    // The following section describes the entry points to this particular
    // driver.  Note that the major function dispatch table must be the last
    // field in the object so that it remains extensible.
    //

    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PVOID MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];

} DRIVER_OBJECT;
typedef struct _DRIVER_OBJECT* PDRIVER_OBJECT;

typedef struct _WAIT_CONTEXT_BLOCK {
    union {
        KDEVICE_QUEUE_ENTRY WaitQueueEntry;
        struct {
            LIST_ENTRY DmaWaitEntry;
            ULONG NumberOfChannels;
            ULONG SyncCallback : 1;
            ULONG DmaContext : 1;
            ULONG ZeroMapRegisters : 1;
            ULONG Reserved : 9;
            ULONG NumberOfRemapPages : 20;
        };
    };
    PVOID DeviceRoutine;
    PVOID DeviceContext;
    ULONG NumberOfMapRegisters;
    PVOID DeviceObject;
    PVOID CurrentIrp;
    PVOID BufferChainingDpc;
} WAIT_CONTEXT_BLOCK, * PWAIT_CONTEXT_BLOCK;

typedef ULONG_PTR KSPIN_LOCK;
typedef struct _KDEVICE_QUEUE {
    CSHORT Type;
    CSHORT Size;
    LIST_ENTRY DeviceListHead;
    KSPIN_LOCK Lock;

#if defined(_AMD64_)

    union {
        BOOLEAN Busy;
        struct {
            LONG64 Reserved : 8;
            LONG64 Hint : 56;
        };
    };

#else

    BOOLEAN Busy;

#endif

} KDEVICE_QUEUE, * PKDEVICE_QUEUE, * PRKDEVICE_QUEUE;

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY* Next;
} SINGLE_LIST_ENTRY, * PSINGLE_LIST_ENTRY;

typedef ULONG_PTR KAFFINITY;
typedef struct _KDPC {
    union {
        ULONG TargetInfoAsUlong;
        struct {
            UCHAR Type;
            UCHAR Importance;
            volatile USHORT Number;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    SINGLE_LIST_ENTRY DpcListEntry;
    KAFFINITY ProcessorHistory;
    PVOID DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    __volatile PVOID DpcData;
} KDPC, * PKDPC, * PRKDPC;

#define TIMER_TOLERABLE_DELAY_BITS      6
#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5

typedef struct _DISPATCHER_HEADER {
    union {
        union {
            volatile LONG Lock;
            LONG LockNV;
        } DUMMYUNIONNAME;

        struct {                            // Events, Semaphores, Gates, etc.
            UCHAR Type;                     // All (accessible via KOBJECT_TYPE)
            UCHAR Signalling;
            UCHAR Size;
            UCHAR Reserved1;
        } DUMMYSTRUCTNAME;

        struct {                            // Timer
            UCHAR TimerType;
            union {
                UCHAR TimerControlFlags;
                struct {
                    UCHAR Absolute : 1;
                    UCHAR Wake : 1;
                    UCHAR EncodedTolerableDelay : TIMER_TOLERABLE_DELAY_BITS;
                } DUMMYSTRUCTNAME;
            };

            UCHAR Hand;
            union {
                UCHAR TimerMiscFlags;
                struct {

#if !defined(KENCODED_TIMER_PROCESSOR)

                    UCHAR Index : TIMER_EXPIRED_INDEX_BITS;

#else

                    UCHAR Index : 1;
                    UCHAR Processor : TIMER_PROCESSOR_INDEX_BITS;

#endif

                    UCHAR Inserted : 1;
                    volatile UCHAR Expired : 1;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;
        } DUMMYSTRUCTNAME2;

        struct {                            // Timer2
            UCHAR Timer2Type;
            union {
                UCHAR Timer2Flags;
                struct {
                    UCHAR Timer2Inserted : 1;
                    UCHAR Timer2Expiring : 1;
                    UCHAR Timer2CancelPending : 1;
                    UCHAR Timer2SetPending : 1;
                    UCHAR Timer2Running : 1;
                    UCHAR Timer2Disabled : 1;
                    UCHAR Timer2ReservedFlags : 2;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;

            UCHAR Timer2ComponentId;
            UCHAR Timer2RelativeId;
        } DUMMYSTRUCTNAME3;

        struct {                            // Queue
            UCHAR QueueType;
            union {
                UCHAR QueueControlFlags;
                struct {
                    UCHAR Abandoned : 1;
                    UCHAR DisableIncrement : 1;
                    UCHAR QueueReservedControlFlags : 6;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;

            UCHAR QueueSize;
            UCHAR QueueReserved;
        } DUMMYSTRUCTNAME4;

        struct {                            // Thread
            UCHAR ThreadType;
            UCHAR ThreadReserved;

            union {
                UCHAR ThreadControlFlags;
                struct {
                    UCHAR CycleProfiling : 1;
                    UCHAR CounterProfiling : 1;
                    UCHAR GroupScheduling : 1;
                    UCHAR AffinitySet : 1;
                    UCHAR Tagged : 1;
                    UCHAR EnergyProfiling : 1;
                    UCHAR SchedulerAssist : 1;

#if !defined(_X86_)

                    UCHAR ThreadReservedControlFlags : 1;

#else

                    UCHAR Instrumented : 1;

#endif

                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;

            union {
                UCHAR DebugActive;

#if !defined(_X86_)

                struct {
                    BOOLEAN ActiveDR7 : 1;
                    BOOLEAN Instrumented : 1;
                    BOOLEAN Minimal : 1;
                    BOOLEAN Reserved4 : 2;
                    BOOLEAN AltSyscall : 1;
                    BOOLEAN Emulation : 1;
                    BOOLEAN Reserved5 : 1;
                } DUMMYSTRUCTNAME;

#endif

            } DUMMYUNIONNAME2;
        } DUMMYSTRUCTNAME5;

        struct {                         // Mutant
            UCHAR MutantType;
            UCHAR MutantSize;
            BOOLEAN DpcActive;
            UCHAR MutantReserved;
        } DUMMYSTRUCTNAME6;
    } DUMMYUNIONNAME;

    LONG SignalState;                   // Object lock
    LIST_ENTRY WaitListHead;            // Object lock
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;

typedef struct _KEVENT {
    DISPATCHER_HEADER Header;
} KEVENT, * PKEVENT, * PRKEVENT;

#define DEVICE_TYPE ULONG
typedef struct _DEVICE_OBJECT {
    CSHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    struct _DRIVER_OBJECT* DriverObject;
    struct _DEVICE_OBJECT* NextDevice;
    struct _DEVICE_OBJECT* AttachedDevice;
    struct _IRP* CurrentIrp;
    PVOID Timer;
    ULONG Flags;                                // See above:  DO_...
    ULONG Characteristics;                      // See ntioapi:  FILE_...
    __volatile PVOID Vpb;
    PVOID DeviceExtension;
    DEVICE_TYPE DeviceType;
    CCHAR StackSize;
    union {
        LIST_ENTRY ListEntry;
        WAIT_CONTEXT_BLOCK Wcb;
    } Queue;
    ULONG AlignmentRequirement;
    KDEVICE_QUEUE DeviceQueue;
    KDPC Dpc;

    //
    //  The following field is for exclusive use by the filesystem to keep
    //  track of the number of Fsp threads currently using the device
    //

    ULONG ActiveThreadCount;
    PVOID SecurityDescriptor;
    KEVENT DeviceLock;

    USHORT SectorSize;
    USHORT Spare1;

    struct _DEVOBJ_EXTENSION* DeviceObjectExtension;
    PVOID  Reserved;

} DEVICE_OBJECT;

typedef struct _LUID {
    ULONG LowPart;
    LONG HighPart;
} LUID, * PLUID;

typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, * PSECURITY_IMPERSONATION_LEVEL;

typedef struct _SECURITY_SUBJECT_CONTEXT {
    PVOID ClientToken;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    PVOID PrimaryToken;
    PVOID ProcessAuditId;
} SECURITY_SUBJECT_CONTEXT, * PSECURITY_SUBJECT_CONTEXT;

typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    ULONG Attributes;
} LUID_AND_ATTRIBUTES, * PLUID_AND_ATTRIBUTES;
typedef LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef LUID_AND_ATTRIBUTES_ARRAY* PLUID_AND_ATTRIBUTES_ARRAY;

typedef struct _PRIVILEGE_SET {
    ULONG PrivilegeCount;
    ULONG Control;
    LUID_AND_ATTRIBUTES Privilege[ANYSIZE_ARRAY];
} PRIVILEGE_SET, * PPRIVILEGE_SET;

#define INITIAL_PRIVILEGE_COUNT         3
typedef struct _INITIAL_PRIVILEGE_SET {
    ULONG PrivilegeCount;
    ULONG Control;
    LUID_AND_ATTRIBUTES Privilege[INITIAL_PRIVILEGE_COUNT];
} INITIAL_PRIVILEGE_SET, * PINITIAL_PRIVILEGE_SET;

typedef struct _ACCESS_STATE {
    LUID OperationID;                // Currently unused, replaced by TransactionId in AUX_ACCESS_DATA
    BOOLEAN SecurityEvaluated;
    BOOLEAN GenerateAudit;
    BOOLEAN GenerateOnClose;
    BOOLEAN PrivilegesAllocated;
    ULONG Flags;
    ACCESS_MASK RemainingDesiredAccess;
    ACCESS_MASK PreviouslyGrantedAccess;
    ACCESS_MASK OriginalDesiredAccess;
    SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
    PVOID SecurityDescriptor; // it stores SD supplied by caller when creating a new object.
    PVOID AuxData;
    union {
        INITIAL_PRIVILEGE_SET InitialPrivilegeSet;
        PRIVILEGE_SET PrivilegeSet;
    } Privileges;

    BOOLEAN AuditPrivileges;
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectTypeName;

} ACCESS_STATE, * PACCESS_STATE;

typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageAdapterProperty,
    StorageDeviceIdProperty,
    StorageDeviceUniqueIdProperty,                  // See storduid.h for details
    StorageDeviceWriteCacheProperty,
    StorageMiniportProperty,
    StorageAccessAlignmentProperty,
    StorageDeviceSeekPenaltyProperty,
    StorageDeviceTrimProperty,
    StorageDeviceWriteAggregationProperty,
    StorageDeviceDeviceTelemetryProperty,
    StorageDeviceLBProvisioningProperty,
    StorageDevicePowerProperty,
    StorageDeviceCopyOffloadProperty,
    StorageDeviceResiliencyProperty,
    StorageDeviceMediumProductType,
    StorageAdapterRpmbProperty,
    StorageAdapterCryptoProperty,
    StorageDeviceIoCapabilityProperty = 48,
    StorageAdapterProtocolSpecificProperty,
    StorageDeviceProtocolSpecificProperty,
    StorageAdapterTemperatureProperty,
    StorageDeviceTemperatureProperty,
    StorageAdapterPhysicalTopologyProperty,
    StorageDevicePhysicalTopologyProperty,
    StorageDeviceAttributesProperty,
    StorageDeviceManagementStatus,
    StorageAdapterSerialNumberProperty,
    StorageDeviceLocationProperty,
    StorageDeviceNumaProperty,
    StorageDeviceZonedDeviceProperty,
    StorageDeviceUnsafeShutdownCount,
    StorageDeviceEnduranceProperty,
    StorageDeviceLedStateProperty,
    StorageDeviceSelfEncryptionProperty = 64,
    StorageFruIdProperty,
} STORAGE_PROPERTY_ID, * PSTORAGE_PROPERTY_ID;

typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0,          // Retrieves the descriptor
    PropertyExistsQuery,                // Used to test whether the descriptor is supported
    PropertyMaskQuery,                  // Used to retrieve a mask of writeable fields in the descriptor
    PropertyQueryMaxDefined     // use to validate the value
} STORAGE_QUERY_TYPE, * PSTORAGE_QUERY_TYPE;

typedef struct _STORAGE_PROPERTY_QUERY {

    //
    // ID of the property being retrieved
    //

    STORAGE_PROPERTY_ID PropertyId;

    //
    // Flags indicating the type of query being performed
    //

    STORAGE_QUERY_TYPE QueryType;

    //
    // Space for additional parameters if necessary
    //

    BYTE  AdditionalParameters[1];

} STORAGE_PROPERTY_QUERY, * PSTORAGE_PROPERTY_QUERY;

typedef
NTSTATUS
IO_COMPLETION_ROUTINE(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_reads_opt_(_Inexpressible_("varies")) PVOID Context
);

typedef IO_COMPLETION_ROUTINE* PIO_COMPLETION_ROUTINE;


typedef _Enum_is_bitflag_ enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,

    //
    // Define base types for NonPaged (versus Paged) pool, for use in cracking
    // the underlying pool type.
    //

    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,

    //
    // Note these per session types are carefully chosen so that the appropriate
    // masking still applies as well as MaxPoolType above.
    //

    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,

    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} _Enum_is_bitflag_ POOL_TYPE;

#pragma warning(push)
#pragma warning(disable:4471)
typedef _Enum_is_bitflag_ enum _POOL_TYPE POOL_TYPE;
#pragma warning(pop)

#define SL_PENDING_RETURNED             0x01
#define SL_ERROR_RETURNED               0x02
#define SL_INVOKE_ON_CANCEL             0x20
#define SL_INVOKE_ON_SUCCESS            0x40
#define SL_INVOKE_ON_ERROR              0x80

typedef enum _STORAGE_BUS_TYPE {
    BusTypeUnknown = 0x00,
    BusTypeScsi,
    BusTypeAtapi,
    BusTypeAta,
    BusType1394,
    BusTypeSsa,
    BusTypeFibre,
    BusTypeUsb,
    BusTypeRAID,
    BusTypeiScsi,
    BusTypeSas,
    BusTypeSata,
    BusTypeSd,
    BusTypeMmc,
    BusTypeVirtual,
    BusTypeFileBackedVirtual,
    BusTypeSpaces,
    BusTypeNvme,
    BusTypeSCM,
    BusTypeUfs,
    BusTypeMax,
    BusTypeMaxReserved = 0x7F
} STORAGE_BUS_TYPE, * PSTORAGE_BUS_TYPE;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {

    //
    // Sizeof(STORAGE_DEVICE_DESCRIPTOR)
    //

        DWORD Version;

    //
    // Total size of the descriptor, including the space for additional
    // data and id strings
    //

        DWORD Size;

    //
    // The SCSI-2 device type
    //

        BYTE  DeviceType;

    //
    // The SCSI-2 device type modifier (if any) - this may be zero
    //

        BYTE  DeviceTypeModifier;

    //
    // Flag indicating whether the device's media (if any) is removable.  This
    // field should be ignored for media-less devices
    //

        BOOLEAN RemovableMedia;

    //
    // Flag indicating whether the device can support mulitple outstanding
    // commands.  The actual synchronization in this case is the responsibility
    // of the port driver.
    //

        BOOLEAN CommandQueueing;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // vendor id string.  For devices with no such ID this will be zero
    //

        DWORD VendorIdOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // product id string.  For devices with no such ID this will be zero
    //

        DWORD ProductIdOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // product revision string.  For devices with no such string this will be
    // zero
    //

        DWORD ProductRevisionOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // serial number.  For devices with no serial number this will be zero
    //

        DWORD SerialNumberOffset;

    //
    // Contains the bus type (as defined above) of the device.  It should be
    // used to interpret the raw device properties at the end of this structure
    // (if any)
    //

        STORAGE_BUS_TYPE BusType;

    //
    // The number of bytes of bus-specific data which have been appended to
    // this descriptor
    //
        DWORD RawPropertiesLength;

    //
    // Place holder for the first byte of the bus specific property data
    //
        BYTE  RawDeviceProperties[1];

} STORAGE_DEVICE_DESCRIPTOR, * PSTORAGE_DEVICE_DESCRIPTOR;

typedef struct _ATA_PASS_THROUGH_EX {
    USHORT Length;
    USHORT AtaFlags;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR ReservedAsUchar;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG ReservedAsUlong;
    ULONG_PTR DataBufferOffset;
    UCHAR PreviousTaskFile[8];
    UCHAR CurrentTaskFile[8];
} ATA_PASS_THROUGH_EX, * PATA_PASS_THROUGH_EX;

#pragma pack(push, id_device_data, 1)
typedef struct _IDENTIFY_DEVICE_DATA {

    struct {
        USHORT Reserved1 : 1;
        USHORT Retired3 : 1;
        USHORT ResponseIncomplete : 1;
        USHORT Retired2 : 3;
        USHORT FixedDevice : 1;                 // obsolete
        USHORT RemovableMedia : 1;              // obsolete
        USHORT Retired1 : 7;
        USHORT DeviceType : 1;
    } GeneralConfiguration;                     // word 0

    USHORT NumCylinders;                        // word 1, obsolete
    USHORT SpecificConfiguration;               // word 2
    USHORT NumHeads;                            // word 3, obsolete
    USHORT Retired1[2];
    USHORT NumSectorsPerTrack;                  // word 6, obsolete
    USHORT VendorUnique1[3];
    UCHAR  SerialNumber[20];                    // word 10-19
    USHORT Retired2[2];
    USHORT Obsolete1;
    UCHAR  FirmwareRevision[8];                 // word 23-26
    UCHAR  ModelNumber[40];                     // word 27-46
    UCHAR  MaximumBlockTransfer;                // word 47. 01h-10h = Maximum number of sectors that shall be transferred per interrupt on READ/WRITE MULTIPLE commands
    UCHAR  VendorUnique2;

    struct {
        USHORT FeatureSupported : 1;
        USHORT Reserved : 15;
    }TrustedComputing;                          // word 48

    struct {
        UCHAR CurrentLongPhysicalSectorAlignment : 2;
        UCHAR ReservedByte49 : 6;

        UCHAR DmaSupported : 1;
        UCHAR LbaSupported : 1;                 // Shall be set to one to indicate that LBA is supported.
        UCHAR IordyDisable : 1;
        UCHAR IordySupported : 1;
        UCHAR Reserved1 : 1;                    // Reserved for the IDENTIFY PACKET DEVICE command
        UCHAR StandybyTimerSupport : 1;
        UCHAR Reserved2 : 2;                    // Reserved for the IDENTIFY PACKET DEVICE command

        USHORT ReservedWord50;
    }Capabilities;                              // word 49-50

    USHORT ObsoleteWords51[2];

    USHORT TranslationFieldsValid : 3;            // word 53, bit 0 - Obsolete; bit 1 - words 70:64 valid; bit 2; word 88 valid
    USHORT Reserved3 : 5;
    USHORT FreeFallControlSensitivity : 8;

    USHORT NumberOfCurrentCylinders;            // word 54, obsolete
    USHORT NumberOfCurrentHeads;                // word 55, obsolete
    USHORT CurrentSectorsPerTrack;              // word 56, obsolete
    ULONG  CurrentSectorCapacity;               // word 57, word 58, obsolete

    UCHAR  CurrentMultiSectorSetting;           // word 59
    UCHAR  MultiSectorSettingValid : 1;
    UCHAR  ReservedByte59 : 3;
    UCHAR  SanitizeFeatureSupported : 1;
    UCHAR  CryptoScrambleExtCommandSupported : 1;
    UCHAR  OverwriteExtCommandSupported : 1;
    UCHAR  BlockEraseExtCommandSupported : 1;

    ULONG  UserAddressableSectors;              // word 60-61, for 28-bit commands

    USHORT ObsoleteWord62;

    USHORT MultiWordDMASupport : 8;             // word 63
    USHORT MultiWordDMAActive : 8;

    USHORT AdvancedPIOModes : 8;                // word 64. bit 0:1 - PIO mode supported
    USHORT ReservedByte64 : 8;

    USHORT MinimumMWXferCycleTime;              // word 65
    USHORT RecommendedMWXferCycleTime;          // word 66
    USHORT MinimumPIOCycleTime;                 // word 67
    USHORT MinimumPIOCycleTimeIORDY;            // word 68

    struct {
        USHORT ZonedCapabilities : 2;
        USHORT NonVolatileWriteCache : 1;                   // All write cache is non-volatile
        USHORT ExtendedUserAddressableSectorsSupported : 1;
        USHORT DeviceEncryptsAllUserData : 1;
        USHORT ReadZeroAfterTrimSupported : 1;
        USHORT Optional28BitCommandsSupported : 1;
        USHORT IEEE1667 : 1;            // Reserved for IEEE 1667
        USHORT DownloadMicrocodeDmaSupported : 1;
        USHORT SetMaxSetPasswordUnlockDmaSupported : 1;
        USHORT WriteBufferDmaSupported : 1;
        USHORT ReadBufferDmaSupported : 1;
        USHORT DeviceConfigIdentifySetDmaSupported : 1;     // obsolete
        USHORT LPSAERCSupported : 1;                        // Long Physical Sector Alignment Error Reporting Control is supported.
        USHORT DeterministicReadAfterTrimSupported : 1;
        USHORT CFastSpecSupported : 1;
    }AdditionalSupported;                       // word 69

    USHORT ReservedWords70[5];                  // word 70 - reserved
                                                // word 71:74 - Reserved for the IDENTIFY PACKET DEVICE command

    //Word 75
    USHORT QueueDepth : 5;          //  Maximum queue depth - 1
    USHORT ReservedWord75 : 11;

    struct {
        // Word 76
        USHORT Reserved0 : 1;    // shall be set to 0
        USHORT SataGen1 : 1;    // Supports SATA Gen1 Signaling Speed (1.5Gb/s)
        USHORT SataGen2 : 1;    // Supports SATA Gen2 Signaling Speed (3.0Gb/s)
        USHORT SataGen3 : 1;    // Supports SATA Gen3 Signaling Speed (6.0Gb/s)

        USHORT Reserved1 : 4;

        USHORT NCQ : 1;    // Supports the NCQ feature set
        USHORT HIPM : 1;    // Supports HIPM
        USHORT PhyEvents : 1;    // Supports the SATA Phy Event Counters log
        USHORT NcqUnload : 1;    // Supports Unload while NCQ commands are outstanding

        USHORT NcqPriority : 1;    // Supports NCQ priority information
        USHORT HostAutoPS : 1;    // Supports Host Automatic Partial to Slumber transitions
        USHORT DeviceAutoPS : 1;    // Supports Device Automatic Partial to Slumber transitions
        USHORT ReadLogDMA : 1;    // Supports READ LOG DMA EXT as equivalent to READ LOG EXT

    // Word 77
        USHORT Reserved2 : 1;                // shall be set to 0
        USHORT CurrentSpeed : 3;                // Coded value indicating current negotiated Serial ATA signal speed

        USHORT NcqStreaming : 1;                // Supports NCQ Streaming
        USHORT NcqQueueMgmt : 1;                // Supports NCQ Queue Management Command
        USHORT NcqReceiveSend : 1;              // Supports RECEIVE FPDMA QUEUED and SEND FPDMA QUEUED commands
        USHORT DEVSLPtoReducedPwrState : 1;

        USHORT Reserved3 : 8;
    }SerialAtaCapabilities;

    // Word 78
    struct {
        USHORT Reserved0 : 1;                //shall be set to 0
        USHORT NonZeroOffsets : 1;                // Device supports non-zero buffer offsets in DMA Setup FIS
        USHORT DmaSetupAutoActivate : 1;          // Device supports DMA Setup auto-activation
        USHORT DIPM : 1;                // Device supports DIPM

        USHORT InOrderData : 1;                // Device supports in-order data delivery
        USHORT HardwareFeatureControl : 1;        // Hardware Feature Control is supported
        USHORT SoftwareSettingsPreservation : 1;  // Device supports Software Settings Preservation
        USHORT NCQAutosense : 1;                  // Supports NCQ Autosense

        USHORT DEVSLP : 1;         // Device supports link power state - device sleep
        USHORT HybridInformation : 1;         // Device supports Hybrid Information Feature (If the device does not support NCQ (word 76 bit 8 is 0), then this bit shall be cleared to 0.)

        USHORT Reserved1 : 6;
    }SerialAtaFeaturesSupported;

    // Word 79
    struct {
        USHORT Reserved0 : 1;                // shall be set to 0
        USHORT NonZeroOffsets : 1;                // Non-zero buffer offsets in DMA Setup FIS enabled
        USHORT DmaSetupAutoActivate : 1;          // DMA Setup auto-activation optimization enabled
        USHORT DIPM : 1;                // DIPM enabled

        USHORT InOrderData : 1;                // In-order data delivery enabled
        USHORT HardwareFeatureControl : 1;        // Hardware Feature Control is enabled
        USHORT SoftwareSettingsPreservation : 1;  // Software Settings Preservation enabled
        USHORT DeviceAutoPS : 1;                // Device Automatic Partial to Slumber transitions enabled

        USHORT DEVSLP : 1;         // link power state - device sleep is enabled
        USHORT HybridInformation : 1;         // Hybrid Information Feature is enabled

        USHORT Reserved1 : 6;
    }SerialAtaFeaturesEnabled;

    USHORT MajorRevision;                       // word 80. bit 5 - supports ATA5; bit 6 - supports ATA6; bit 7 - supports ATA7; bit 8 - supports ATA8-ACS; bit 9 - supports ACS-2;
    USHORT MinorRevision;                       // word 81. T13 minior version number

    struct {

        //
        // Word 82
        //
        USHORT SmartCommands : 1;           // The SMART feature set is supported
        USHORT SecurityMode : 1;            // The Security feature set is supported
        USHORT RemovableMediaFeature : 1;   // obsolete
        USHORT PowerManagement : 1;         // shall be set to 1
        USHORT Reserved1 : 1;               // PACKET feature set, set to 0 indicates not supported for ATA devices (only support for ATAPI devices)
        USHORT WriteCache : 1;              // The volatile write cache is supported
        USHORT LookAhead : 1;               // Read look-ahead is supported
        USHORT ReleaseInterrupt : 1;        // obsolete
        USHORT ServiceInterrupt : 1;        // obsolete
        USHORT DeviceReset : 1;             // Shall be cleared to zero to indicate that the DEVICE RESET command is not supported
        USHORT HostProtectedArea : 1;       // obsolete
        USHORT Obsolete1 : 1;
        USHORT WriteBuffer : 1;             // The WRITE BUFFER command is supported
        USHORT ReadBuffer : 1;              // The READ BUFFER command is supported
        USHORT Nop : 1;                     // The NOP command is supported
        USHORT Obsolete2 : 1;

        //
        // Word 83
        //
        USHORT DownloadMicrocode : 1;       // The DOWNLOAD MICROCODE command is supported
        USHORT DmaQueued : 1;               // obsolete
        USHORT Cfa : 1;                     // The CFA feature set is supported
        USHORT AdvancedPm : 1;              // The APM feature set is supported
        USHORT Msn : 1;                     // obsolete
        USHORT PowerUpInStandby : 1;        // The PUIS feature set is supported
        USHORT ManualPowerUp : 1;           // SET FEATURES subcommand is required to spin-up after power-up
        USHORT Reserved2 : 1;
        USHORT SetMax : 1;                  // obsolete
        USHORT Acoustics : 1;               // obsolete
        USHORT BigLba : 1;                  // The 48-bit Address feature set is supported
        USHORT DeviceConfigOverlay : 1;     // obsolete
        USHORT FlushCache : 1;              // Shall be set to one to indicate that the mandatory FLUSH CACHE command is supported
        USHORT FlushCacheExt : 1;           // The FLUSH CACHE EXT command is supported
        USHORT WordValid83 : 2;             // shall be 01b


        //
        // Word 84
        //
        USHORT SmartErrorLog : 1;           // SMART error logging is supported
        USHORT SmartSelfTest : 1;           // The SMART self-test is supported
        USHORT MediaSerialNumber : 1;       // Media serial number is supported
        USHORT MediaCardPassThrough : 1;    // obsolete
        USHORT StreamingFeature : 1;        // The Streaming feature set is supported
        USHORT GpLogging : 1;               // The GPL feature set is supported
        USHORT WriteFua : 1;                // The WRITE DMA FUA EXT and WRITE MULTIPLE FUA EXT commands are supported
        USHORT WriteQueuedFua : 1;          // obsolete
        USHORT WWN64Bit : 1;                // The 64-bit World wide name is supported
        USHORT URGReadStream : 1;           // obsolete
        USHORT URGWriteStream : 1;          // obsolete
        USHORT ReservedForTechReport : 2;
        USHORT IdleWithUnloadFeature : 1;   // The IDLE IMMEDIATE command with UNLOAD feature is supported
        USHORT WordValid : 2;               // shall be 01b

    }CommandSetSupport;

    struct {

        //
        // Word 85
        //
        USHORT SmartCommands : 1;           // The SMART feature set is enabled
        USHORT SecurityMode : 1;            // The Security feature set is enabled
        USHORT RemovableMediaFeature : 1;   // obsolete
        USHORT PowerManagement : 1;         // Shall be set to one to indicate that the mandatory Power Management feature set is supported
        USHORT Reserved1 : 1;               // Shall be cleared to zero to indicate that the PACKET feature set is not supported
        USHORT WriteCache : 1;              // The volatile write cache is enabled
        USHORT LookAhead : 1;               // Read look-ahead is enabled
        USHORT ReleaseInterrupt : 1;        // The release interrupt is enabled
        USHORT ServiceInterrupt : 1;        // The SERVICE interrupt is enabled
        USHORT DeviceReset : 1;             // Shall be cleared to zero to indicate that the DEVICE RESET command is not supported
        USHORT HostProtectedArea : 1;       // obsolete
        USHORT Obsolete1 : 1;
        USHORT WriteBuffer : 1;             // The WRITE BUFFER command is supported
        USHORT ReadBuffer : 1;              // The READ BUFFER command is supported
        USHORT Nop : 1;                     // The NOP command is supported
        USHORT Obsolete2 : 1;

        //
        // Word 86
        //
        USHORT DownloadMicrocode : 1;       // The DOWNLOAD MICROCODE command is supported
        USHORT DmaQueued : 1;               // obsolete
        USHORT Cfa : 1;                     // The CFA feature set is supported
        USHORT AdvancedPm : 1;              // The APM feature set is enabled
        USHORT Msn : 1;                     // obsolete
        USHORT PowerUpInStandby : 1;        // The PUIS feature set is enabled
        USHORT ManualPowerUp : 1;           // SET FEATURES subcommand is required to spin-up after power-up
        USHORT Reserved2 : 1;
        USHORT SetMax : 1;                  // obsolete
        USHORT Acoustics : 1;               // obsolete
        USHORT BigLba : 1;                  // The 48-bit Address features set is supported
        USHORT DeviceConfigOverlay : 1;     // obsolete
        USHORT FlushCache : 1;              // FLUSH CACHE command supported
        USHORT FlushCacheExt : 1;           // FLUSH CACHE EXT command supported
        USHORT Resrved3 : 1;
        USHORT Words119_120Valid : 1;       // Words 119..120 are valid

        //
        // Word 87
        //
        USHORT SmartErrorLog : 1;           // SMART error logging is supported
        USHORT SmartSelfTest : 1;           // SMART self-test supported
        USHORT MediaSerialNumber : 1;       // Media serial number is valid
        USHORT MediaCardPassThrough : 1;    // obsolete
        USHORT StreamingFeature : 1;        // obsolete
        USHORT GpLogging : 1;               // The GPL feature set is supported
        USHORT WriteFua : 1;                // The WRITE DMA FUA EXT and WRITE MULTIPLE FUA EXT commands are supported
        USHORT WriteQueuedFua : 1;          // obsolete
        USHORT WWN64Bit : 1;                // The 64-bit World wide name is supported
        USHORT URGReadStream : 1;           // obsolete
        USHORT URGWriteStream : 1;          // obsolete
        USHORT ReservedForTechReport : 2;
        USHORT IdleWithUnloadFeature : 1;   // The IDLE IMMEDIATE command with UNLOAD FEATURE is supported
        USHORT Reserved4 : 2;               // bit 14 shall be set to 1; bit 15 shall be cleared to 0

    }CommandSetActive;

    USHORT UltraDMASupport : 8;                 // word 88. bit 0 - UDMA mode 0 is supported ... bit 6 - UDMA mode 6 and below are supported
    USHORT UltraDMAActive : 8;                 // word 88. bit 8 - UDMA mode 0 is selected ... bit 14 - UDMA mode 6 is selected

    struct {                                    // word 89
        USHORT TimeRequired : 15;
        USHORT ExtendedTimeReported : 1;
    } NormalSecurityEraseUnit;

    struct {                                    // word 90
        USHORT TimeRequired : 15;
        USHORT ExtendedTimeReported : 1;
    } EnhancedSecurityEraseUnit;

    USHORT CurrentAPMLevel : 8;                 // word 91
    USHORT ReservedWord91 : 8;

    USHORT MasterPasswordID;                    // word 92. Master Password Identifier

    USHORT HardwareResetResult;                 // word 93

    USHORT CurrentAcousticValue : 8;            // word 94. obsolete
    USHORT RecommendedAcousticValue : 8;

    USHORT StreamMinRequestSize;                // word 95
    USHORT StreamingTransferTimeDMA;            // word 96
    USHORT StreamingAccessLatencyDMAPIO;        // word 97
    ULONG  StreamingPerfGranularity;            // word 98, 99

    ULONG  Max48BitLBA[2];                      // word 100-103

    USHORT StreamingTransferTime;               // word 104. Streaming Transfer Time - PIO

    USHORT DsmCap;                              // word 105

    struct {
        USHORT LogicalSectorsPerPhysicalSector : 4;         // n power of 2: logical sectors per physical sector
        USHORT Reserved0 : 8;
        USHORT LogicalSectorLongerThan256Words : 1;
        USHORT MultipleLogicalSectorsPerPhysicalSector : 1;
        USHORT Reserved1 : 2;                               // bit 14 - shall be set to  1; bit 15 - shall be clear to 0
    } PhysicalLogicalSectorSize;                // word 106

    USHORT InterSeekDelay;                      //word 107.     Inter-seek delay for ISO 7779 standard acoustic testing
    USHORT WorldWideName[4];                    //words 108-111
    USHORT ReservedForWorldWideName128[4];      //words 112-115
    USHORT ReservedForTlcTechnicalReport;       //word 116
    USHORT WordsPerLogicalSector[2];            //words 117-118 Logical sector size (DWord)

    struct {
        USHORT ReservedForDrqTechnicalReport : 1;
        USHORT WriteReadVerify : 1;                 // The Write-Read-Verify feature set is supported
        USHORT WriteUncorrectableExt : 1;           // The WRITE UNCORRECTABLE EXT command is supported
        USHORT ReadWriteLogDmaExt : 1;              // The READ LOG DMA EXT and WRITE LOG DMA EXT commands are supported
        USHORT DownloadMicrocodeMode3 : 1;          // Download Microcode mode 3 is supported
        USHORT FreefallControl : 1;                 // The Free-fall Control feature set is supported
        USHORT SenseDataReporting : 1;              // Sense Data Reporting feature set is supported
        USHORT ExtendedPowerConditions : 1;         // Extended Power Conditions feature set is supported
        USHORT Reserved0 : 6;
        USHORT WordValid : 2;                       // shall be 01b
    }CommandSetSupportExt;                      //word 119

    struct {
        USHORT ReservedForDrqTechnicalReport : 1;
        USHORT WriteReadVerify : 1;                 // The Write-Read-Verify feature set is enabled
        USHORT WriteUncorrectableExt : 1;           // The WRITE UNCORRECTABLE EXT command is supported
        USHORT ReadWriteLogDmaExt : 1;              // The READ LOG DMA EXT and WRITE LOG DMA EXT commands are supported
        USHORT DownloadMicrocodeMode3 : 1;          // Download Microcode mode 3 is supported
        USHORT FreefallControl : 1;                 // The Free-fall Control feature set is enabled
        USHORT SenseDataReporting : 1;              // Sense Data Reporting feature set is enabled
        USHORT ExtendedPowerConditions : 1;         // Extended Power Conditions feature set is enabled
        USHORT Reserved0 : 6;
        USHORT Reserved1 : 2;                       // bit 14 - shall be set to  1; bit 15 - shall be clear to 0
    }CommandSetActiveExt;                       //word 120

    USHORT ReservedForExpandedSupportandActive[6];

    USHORT MsnSupport : 2;                      //word 127. obsolete
    USHORT ReservedWord127 : 14;

    struct {                                    //word 128
        USHORT SecuritySupported : 1;
        USHORT SecurityEnabled : 1;
        USHORT SecurityLocked : 1;
        USHORT SecurityFrozen : 1;
        USHORT SecurityCountExpired : 1;
        USHORT EnhancedSecurityEraseSupported : 1;
        USHORT Reserved0 : 2;
        USHORT SecurityLevel : 1;                   // Master Password Capability: 0 = High, 1 = Maximum
        USHORT Reserved1 : 7;
    } SecurityStatus;

    USHORT ReservedWord129[31];                 //word 129...159. Vendor specific

    struct {                                    //word 160
        USHORT MaximumCurrentInMA : 12;
        USHORT CfaPowerMode1Disabled : 1;
        USHORT CfaPowerMode1Required : 1;
        USHORT Reserved0 : 1;
        USHORT Word160Supported : 1;
    } CfaPowerMode1;

    USHORT ReservedForCfaWord161[7];                //Words 161-167

    USHORT NominalFormFactor : 4;                   //Word 168
    USHORT ReservedWord168 : 12;

    struct {                                        //Word 169
        USHORT SupportsTrim : 1;
        USHORT Reserved0 : 15;
    } DataSetManagementFeature;

    USHORT AdditionalProductID[4];                  //Words 170-173

    USHORT ReservedForCfaWord174[2];                //Words 174-175

    USHORT CurrentMediaSerialNumber[30];            //Words 176-205

    struct {                                        //Word 206
        USHORT Supported : 1;                           // The SCT Command Transport is supported
        USHORT Reserved0 : 1;                           // obsolete
        USHORT WriteSameSuported : 1;                   // The SCT Write Same command is supported
        USHORT ErrorRecoveryControlSupported : 1;       // The SCT Error Recovery Control command is supported
        USHORT FeatureControlSuported : 1;              // The SCT Feature Control command is supported
        USHORT DataTablesSuported : 1;                  // The SCT Data Tables command is supported
        USHORT Reserved1 : 6;
        USHORT VendorSpecific : 4;
    } SCTCommandTransport;

    USHORT ReservedWord207[2];                      //Words 207-208

    struct {                                        //Word 209
        USHORT AlignmentOfLogicalWithinPhysical : 14;
        USHORT Word209Supported : 1;                     // shall be set to 1
        USHORT Reserved0 : 1;                            // shall be cleared to 0
    } BlockAlignment;

    USHORT WriteReadVerifySectorCountMode3Only[2];  //Words 210-211
    USHORT WriteReadVerifySectorCountMode2Only[2];  //Words 212-213

    struct {
        USHORT NVCachePowerModeEnabled : 1;
        USHORT Reserved0 : 3;
        USHORT NVCacheFeatureSetEnabled : 1;
        USHORT Reserved1 : 3;
        USHORT NVCachePowerModeVersion : 4;
        USHORT NVCacheFeatureSetVersion : 4;
    } NVCacheCapabilities;                  //Word 214. obsolete
    USHORT NVCacheSizeLSW;                  //Word 215. obsolete
    USHORT NVCacheSizeMSW;                  //Word 216. obsolete

    USHORT NominalMediaRotationRate;        //Word 217; value 0001h means non-rotating media.

    USHORT ReservedWord218;                 //Word 218

    struct {
        UCHAR NVCacheEstimatedTimeToSpinUpInSeconds;
        UCHAR Reserved;
    } NVCacheOptions;                       //Word 219. obsolete

    USHORT  WriteReadVerifySectorCountMode : 8;     //Word 220. Write-Read-Verify feature set current mode
    USHORT  ReservedWord220 : 8;

    USHORT  ReservedWord221;                //Word 221

    struct {                                //Word 222 Transport major version number
        USHORT  MajorVersion : 12;              // 0000h or FFFFh = device does not report version
        USHORT  TransportType : 4;
    } TransportMajorVersion;

    USHORT  TransportMinorVersion;          // Word 223

    USHORT  ReservedWord224[6];             // Word 224...229

    ULONG   ExtendedNumberOfUserAddressableSectors[2];  // Words 230...233 Extended Number of User Addressable Sectors

    USHORT  MinBlocksPerDownloadMicrocodeMode03;        // Word 234 Minimum number of 512-byte data blocks per Download Microcode mode 03h operation
    USHORT  MaxBlocksPerDownloadMicrocodeMode03;        // Word 235 Maximum number of 512-byte data blocks per Download Microcode mode 03h operation

    USHORT ReservedWord236[19];             // Word 236...254

    USHORT Signature : 8;                   //Word 255
    USHORT CheckSum : 8;

} IDENTIFY_DEVICE_DATA, * PIDENTIFY_DEVICE_DATA;
#pragma pack (pop, id_device_data)

#include <pshpack1.h>
typedef struct _DRIVERSTATUS {
    BYTE     bDriverError;           // Error code from driver,
                                                            // or 0 if no error.
    BYTE     bIDEError;                      // Contents of IDE Error register.
                                                            // Only valid when bDriverError
                                                            // is SMART_IDE_ERROR.
    BYTE     bReserved[2];           // Reserved for future expansion.
    DWORD   dwReserved[2];          // Reserved for future expansion.
} DRIVERSTATUS, * PDRIVERSTATUS, * LPDRIVERSTATUS;
#include <poppack.h>

#include <pshpack1.h>
typedef struct _SENDCMDOUTPARAMS {
    DWORD                   cBufferSize;            // Size of bBuffer in bytes
    DRIVERSTATUS            DriverStatus;           // Driver status structure.
    BYTE                    bBuffer[1];             // Buffer of arbitrary length in which to store the data read from the                                                                                  // drive.
} SENDCMDOUTPARAMS, * PSENDCMDOUTPARAMS, * LPSENDCMDOUTPARAMS;
#include <poppack.h>

typedef struct _IDSECTOR {
    USHORT  wGenConfig;
    USHORT  wNumCyls;
    USHORT  wReserved;
    USHORT  wNumHeads;
    USHORT  wBytesPerTrack;
    USHORT  wBytesPerSector;
    USHORT  wSectorsPerTrack;
    USHORT  wVendorUnique[3];
    CHAR    sSerialNumber[20];
    USHORT  wBufferType;
    USHORT  wBufferSize;
    USHORT  wECCSize;
    CHAR    sFirmwareRev[8];
    CHAR    sModelNumber[40];
    USHORT  wMoreVendorUnique;
    USHORT  wDoubleWordIO;
    USHORT  wCapabilities;
    USHORT  wReserved1;
    USHORT  wPIOTiming;
    USHORT  wDMATiming;
    USHORT  wBS;
    USHORT  wNumCurrentCyls;
    USHORT  wNumCurrentHeads;
    USHORT  wNumCurrentSectorsPerTrack;
    ULONG   ulCurrentSectorCapacity;
    USHORT  wMultSectorStuff;
    ULONG   ulTotalAddressableSectors;
    USHORT  wSingleWordDMA;
    USHORT  wMultiWordDMA;
    BYTE    bReserved[128];
} IDSECTOR, * PIDSECTOR;

typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID;

typedef struct  _PARTITION_INFORMATION_MBR {

    
        UCHAR PartitionType;

    
        BOOLEAN BootIndicator;

    
        BOOLEAN RecognizedPartition;

    
        ULONG HiddenSectors;

#if (NTDDI_VERSION >= NTDDI_WINBLUE)    /* ABRACADABRA_THRESHOLD */
    
        GUID PartitionId;
#endif

} PARTITION_INFORMATION_MBR, * PPARTITION_INFORMATION_MBR;

typedef struct  _PARTITION_INFORMATION_GPT {

    
        GUID PartitionType;                 // Partition type. See table 16-3.

    
        GUID PartitionId;                   // Unique GUID for this partition.

    
        ULONG64 Attributes;                 // See table 16-4.

    
        WCHAR Name[36];                    // Partition Name in Unicode.

} PARTITION_INFORMATION_GPT, * PPARTITION_INFORMATION_GPT;


typedef enum  _PARTITION_STYLE {
    PARTITION_STYLE_MBR,
    PARTITION_STYLE_GPT,
    PARTITION_STYLE_RAW
} PARTITION_STYLE;

typedef struct _PARTITION_INFORMATION_EX {

  
        PARTITION_STYLE PartitionStyle;

    
        LARGE_INTEGER StartingOffset;

    
        LARGE_INTEGER PartitionLength;

    
        ULONG PartitionNumber;

    
        BOOLEAN RewritePartition;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)  /* ABRACADABRA_WIN10_RS3 */
    
        BOOLEAN IsServicePartition;
#endif

    union {

        
            PARTITION_INFORMATION_MBR Mbr;

        
            PARTITION_INFORMATION_GPT Gpt;

    } /*DUMMYUNIONNAME*/;

} PARTITION_INFORMATION_EX, * PPARTITION_INFORMATION_EX;

typedef struct  _DRIVE_LAYOUT_INFORMATION_MBR {

    
        ULONG Signature;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)  /* ABRACADABRA_WIN10_RS1 */
    ULONG CheckSum;
#endif

} DRIVE_LAYOUT_INFORMATION_MBR, * PDRIVE_LAYOUT_INFORMATION_MBR;

typedef struct  _DRIVE_LAYOUT_INFORMATION_GPT {

    
        GUID DiskId;

    
        LARGE_INTEGER StartingUsableOffset;

    
        LARGE_INTEGER UsableLength;

    
        ULONG MaxPartitionCount;

} DRIVE_LAYOUT_INFORMATION_GPT, * PDRIVE_LAYOUT_INFORMATION_GPT;

typedef struct  _DRIVE_LAYOUT_INFORMATION_EX {

    
        ULONG PartitionStyle;

    
        ULONG PartitionCount;

    union {

        
            DRIVE_LAYOUT_INFORMATION_MBR Mbr;

        
            DRIVE_LAYOUT_INFORMATION_GPT Gpt;

    } ;

    
        PARTITION_INFORMATION_EX PartitionEntry[1];

} DRIVE_LAYOUT_INFORMATION_EX, * PDRIVE_LAYOUT_INFORMATION_EX;

typedef struct _SRB_IO_CONTROL {
    ULONG HeaderLength;
    UCHAR Signature[8];
    ULONG Timeout;
    ULONG ControlCode;
    ULONG ReturnCode;
    ULONG Length;
} SRB_IO_CONTROL, * PSRB_IO_CONTROL;

typedef enum _STORAGE_PROTOCOL_TYPE {
    ProtocolTypeUnknown = 0,
    ProtocolTypeScsi,
    ProtocolTypeAta,
    ProtocolTypeNvme,
    ProtocolTypeSd
} STORAGE_PROTOCOL_TYPE;

typedef struct _STORAGE_PROTOCOL_SPECIFIC_DATA {
    STORAGE_PROTOCOL_TYPE ProtocolType;
    ULONG DataType;
    ULONG ProtocolDataRequestValue;
    ULONG ProtocolDataRequestSubValue;
    ULONG ProtocolDataOffset;
    ULONG ProtocolDataLength;
    ULONG FixedProtocolReturnData;
    ULONG Reserved[3];
} STORAGE_PROTOCOL_SPECIFIC_DATA;

struct STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER
{
    struct { // STORAGE_PROPERTY_QUERY without AdditionalsParameters[1]
        STORAGE_PROPERTY_ID PropertyId;
        STORAGE_QUERY_TYPE QueryType;
    } PropertyQuery;
    STORAGE_PROTOCOL_SPECIFIC_DATA ProtocolSpecific;
    BYTE DataBuffer[1];
};

struct nvme_id_power_state {
    unsigned short  max_power; // centiwatts
    unsigned char   rsvd2;
    unsigned char   flags;
    unsigned int    entry_lat; // microseconds
    unsigned int    exit_lat;  // microseconds
    unsigned char   read_tput;
    unsigned char   read_lat;
    unsigned char   write_tput;
    unsigned char   write_lat;
    unsigned short  idle_power;
    unsigned char   idle_scale;
    unsigned char   rsvd19;
    unsigned short  active_power;
    unsigned char   active_work_scale;
    unsigned char   rsvd23[9];
};

struct nvme_id_ctrl {
    unsigned short  vid;
    unsigned short  ssvid;
    char            sn[20];
    char            mn[40];
    char            fr[8];
    unsigned char   rab;
    unsigned char   ieee[3];
    unsigned char   cmic;
    unsigned char   mdts;
    unsigned short  cntlid;
    unsigned int    ver;
    unsigned int    rtd3r;
    unsigned int    rtd3e;
    unsigned int    oaes;
    unsigned int    ctratt;
    unsigned char   rsvd100[156];
    unsigned short  oacs;
    unsigned char   acl;
    unsigned char   aerl;
    unsigned char   frmw;
    unsigned char   lpa;
    unsigned char   elpe;
    unsigned char   npss;
    unsigned char   avscc;
    unsigned char   apsta;
    unsigned short  wctemp;
    unsigned short  cctemp;
    unsigned short  mtfa;
    unsigned int    hmpre;
    unsigned int    hmmin;
    unsigned char   tnvmcap[16];
    unsigned char   unvmcap[16];
    unsigned int    rpmbs;
    unsigned short  edstt;
    unsigned char   dsto;
    unsigned char   fwug;
    unsigned short  kas;
    unsigned short  hctma;
    unsigned short  mntmt;
    unsigned short  mxtmt;
    unsigned int    sanicap;
    unsigned char   rsvd332[180];
    unsigned char   sqes;
    unsigned char   cqes;
    unsigned short  maxcmd;
    unsigned int    nn;
    unsigned short  oncs;
    unsigned short  fuses;
    unsigned char   fna;
    unsigned char   vwc;
    unsigned short  awun;
    unsigned short  awupf;
    unsigned char   nvscc;
    unsigned char   rsvd531;
    unsigned short  acwu;
    unsigned char   rsvd534[2];
    unsigned int    sgls;
    unsigned char   rsvd540[228];
    char			      subnqn[256];
    unsigned char   rsvd1024[768];
    unsigned int    ioccsz;
    unsigned int    iorcsz;
    unsigned short  icdoff;
    unsigned char   ctrattr;
    unsigned char   msdbd;
    unsigned char   rsvd1804[244];
    struct nvme_id_power_state  psd[32];
    unsigned char   vs[1024];
};

typedef struct _SCSI_PASS_THROUGH_DIRECT {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    PVOID DataBuffer;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
}SCSI_PASS_THROUGH_DIRECT, * PSCSI_PASS_THROUGH_DIRECT;

typedef struct {
    SCSI_PASS_THROUGH_DIRECT spt;
    ULONG           Filler;
    UCHAR           ucSenseBuf[64];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;

#define SCSI_IOCTL_DATA_OUT          0
#define SCSI_IOCTL_DATA_IN           1
#define SCSI_IOCTL_DATA_UNSPECIFIED  2


//
// Protocol Data should follow this data structure in the same buffer.
// The offset of Protocol Data from the beginning of this data structure
// is reported in data field - "ProtocolDataOffset".
//
typedef struct _STORAGE_PROTOCOL_SPECIFIC_DATA2 {

    STORAGE_PROTOCOL_TYPE ProtocolType;
    DWORD   DataType;                     // The value will be protocol specific, as defined in STORAGE_PROTOCOL_NVME_DATA_TYPE or STORAGE_PROTOCOL_ATA_DATA_TYPE.

    DWORD   ProtocolDataRequestValue;
    DWORD   ProtocolDataRequestSubValue;  // Data sub request value

    DWORD   ProtocolDataOffset;           // The offset of data buffer is from beginning of this data structure.
    DWORD   ProtocolDataLength;

    DWORD   FixedProtocolReturnData;
    DWORD   ProtocolDataRequestSubValue2; // First additional data sub request value

    DWORD   ProtocolDataRequestSubValue3; // Second additional data sub request value
    DWORD   ProtocolDataRequestSubValue4; // Third additional data sub request value

} STORAGE_PROTOCOL_SPECIFIC_DATA2, * PSTORAGE_PROTOCOL_SPECIFIC_DATA2;
