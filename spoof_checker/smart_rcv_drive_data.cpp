#include "ioctl_base.hpp"

//  SENDCMDINPARAMS contains the input parameters for the 
//  Send Command to Drive function.
//typedef struct _SENDCMDINPARAMS
//{
//	DWORD     cBufferSize;   //  Buffer size in bytes
//	IDEREGS   irDriveRegs;   //  Structure with drive register values.
//	BYTE bDriveNumber;       //  Physical drive number to send 
//							 //  command to (0,1,2,3).
//	BYTE bReserved[3];       //  Reserved for future expansion.
//	DWORD     dwReserved[4]; //  For future use.
//	BYTE      bBuffer[1];    //  Input buffer.
//} SENDCMDINPARAMS, * PSENDCMDINPARAMS, * LPSENDCMDINPARAMS;

//
// IDENTIFY data (from ATAPI driver source)
//

#pragma pack(1)

typedef struct _IDENTIFY_DATA {
    USHORT GeneralConfiguration;            // 00 00
    USHORT NumberOfCylinders;               // 02  1
    USHORT Reserved1;                       // 04  2
    USHORT NumberOfHeads;                   // 06  3
    USHORT UnformattedBytesPerTrack;        // 08  4
    USHORT UnformattedBytesPerSector;       // 0A  5
    USHORT SectorsPerTrack;                 // 0C  6
    USHORT VendorUnique1[3];                // 0E  7-9
    USHORT SerialNumber[10];                // 14  10-19
    USHORT BufferType;                      // 28  20
    USHORT BufferSectorSize;                // 2A  21
    USHORT NumberOfEccBytes;                // 2C  22
    USHORT FirmwareRevision[4];             // 2E  23-26
    USHORT ModelNumber[20];                 // 36  27-46
    UCHAR  MaximumBlockTransfer;            // 5E  47
    UCHAR  VendorUnique2;                   // 5F
    USHORT DoubleWordIo;                    // 60  48
    USHORT Capabilities;                    // 62  49
    USHORT Reserved2;                       // 64  50
    UCHAR  VendorUnique3;                   // 66  51
    UCHAR  PioCycleTimingMode;              // 67
    UCHAR  VendorUnique4;                   // 68  52
    UCHAR  DmaCycleTimingMode;              // 69
    USHORT TranslationFieldsValid : 1;        // 6A  53
    USHORT Reserved3 : 15;
    USHORT NumberOfCurrentCylinders;        // 6C  54
    USHORT NumberOfCurrentHeads;            // 6E  55
    USHORT CurrentSectorsPerTrack;          // 70  56
    ULONG  CurrentSectorCapacity;           // 72  57-58
    USHORT CurrentMultiSectorSetting;       //     59
    ULONG  UserAddressableSectors;          //     60-61
    USHORT SingleWordDMASupport : 8;        //     62
    USHORT SingleWordDMAActive : 8;
    USHORT MultiWordDMASupport : 8;         //     63
    USHORT MultiWordDMAActive : 8;
    USHORT AdvancedPIOModes : 8;            //     64
    USHORT Reserved4 : 8;
    USHORT MinimumMWXferCycleTime;          //     65
    USHORT RecommendedMWXferCycleTime;      //     66
    USHORT MinimumPIOCycleTime;             //     67
    USHORT MinimumPIOCycleTimeIORDY;        //     68
    USHORT Reserved5[2];                    //     69-70
    USHORT ReleaseTimeOverlapped;           //     71
    USHORT ReleaseTimeServiceCommand;       //     72
    USHORT MajorRevision;                   //     73
    USHORT MinorRevision;                   //     74
    USHORT Reserved6[50];                   //     75-126
    USHORT SpecialFunctionsEnabled;         //     127
    USHORT Reserved7[128];                  //     128-255
} IDENTIFY_DATA, * PIDENTIFY_DATA;

#pragma pack()

char* convert_to_string(DWORD *diskdata,
    int firstIndex,
    int lastIndex,
    char* buf)
{
    int index = 0;
    int position = 0;

    //  each integer has two characters stored in it backwards
    for (index = firstIndex; index <= lastIndex; index++)
    {
        //  get high byte for 1st character
        buf[position++] = (char)(diskdata[index] / 256);

        //  get low byte for 2nd character
        buf[position++] = (char)(diskdata[index] % 256);
    }

    //  end the string 
    buf[position] = '\0';

    //  cut off the trailing blanks
    for (index = position - 1; index > 0 && isspace(buf[index]); index--)
        buf[index] = '\0';

    return buf;
}


void smart_rcv_drive_data::trigger()
{
	auto command_size = sizeof(SENDCMDINPARAMS) + IDENTIFY_BUFFER_SIZE;
	auto command = (SENDCMDINPARAMS*)new uint8_t[command_size];

	command->irDriveRegs.bCommandReg = 0xEC; //ID_CMD
	
	if (send_ioctl(command, sizeof(SENDCMDINPARAMS), command, command_size))
	{
		DWORD disk_data[256] = { 0 };
		auto* id_sector = (USHORT*)(PIDENTIFY_DATA)((PSENDCMDOUTPARAMS)command)->bBuffer;

        for (int ijk = 0; ijk < 256; ijk++)
            disk_data[ijk] = id_sector[ijk];

        char serial_number[256] = { 0 };
        convert_to_string(disk_data, 10, 19, serial_number);

        print_serial(serial_number);
	}

	delete[] command;
}