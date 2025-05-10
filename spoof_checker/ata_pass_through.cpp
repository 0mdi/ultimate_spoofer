#include "ioctl_base.hpp"

#include <ntddscsi.h>
#include <ntddstor.h>

#define IDE_COMMAND_IDENTIFY                    0xEC

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
        USHORT Reserved : 2;
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

static void SwapEndianness(void* ptr, size_t size)
{
    struct u16
    {
        uint8_t high;
        uint8_t low;
    };

    for (u16* pStruct = (u16*)ptr; pStruct < (u16*)ptr + size / 2; pStruct++)
        std::swap(pStruct->low, pStruct->high);
}


void ata_pass_through::trigger()
{
    char buffer[512 + sizeof(ATA_PASS_THROUGH_EX)] = { 0 };
    ATA_PASS_THROUGH_EX& PTE = *(ATA_PASS_THROUGH_EX*)buffer;
    IDEREGS* ir = (IDEREGS*)PTE.CurrentTaskFile;
    DWORD bytes = 0;

    PTE.AtaFlags = ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED;
    PTE.Length = sizeof(PTE);
    PTE.DataTransferLength = 512;
    PTE.TimeOutValue = 10;
    PTE.DataBufferOffset = sizeof(PTE);

    ir->bCommandReg = IDE_COMMAND_IDENTIFY;

    if (send_ioctl(&PTE, sizeof(PTE), buffer, sizeof(buffer)))
    {
        auto disk_info = (PIDENTIFY_DEVICE_DATA)(buffer + sizeof(PTE));

        SwapEndianness(disk_info->SerialNumber, sizeof(disk_info->SerialNumber));
        print_serial((char*)disk_info->SerialNumber);
    }
}