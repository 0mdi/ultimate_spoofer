#include "ioctl_base.hpp"

#include <ntddscsi.h>


char scsi_buf[0x1000] = { 0 };

#define  SENDIDLENGTH  sizeof (SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE

#define  IOCTL_SCSI_MINIPORT_IDENTIFY  ((FILE_DEVICE_SCSI << 16) + 0x0501)

//  Valid values for the bCommandReg member of IDEREGS.
#define  IDE_ATAPI_IDENTIFY  0xA1  //  Returns ID sector for ATAPI.
#define  IDE_ATA_IDENTIFY    0xEC  //  Returns ID sector for ATA.

   // The following struct defines the interesting part of the IDENTIFY
   // buffer:
typedef struct _IDSECTOR
{
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

char* ConvertToString(DWORD diskdata[256],
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

void scsi_miniport::trigger()
{
	memset(scsi_buf, 0, sizeof(scsi_buf));
	auto srb = (SRB_IO_CONTROL*)scsi_buf;
	auto in = (SENDCMDINPARAMS*)(scsi_buf + sizeof(SRB_IO_CONTROL));
	srb->HeaderLength = sizeof(SRB_IO_CONTROL);
	srb->Timeout = 10000;
	srb->Length = SENDIDLENGTH;
	strncpy((char*)srb->Signature, "SCSIDISK", 8);
	srb->ControlCode = IOCTL_SCSI_MINIPORT_IDENTIFY;

	in->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;
	in->bDriveNumber = m_drive;

	if (send_ioctl(scsi_buf, sizeof(SRB_IO_CONTROL) + sizeof(SENDCMDINPARAMS) - 1,
		scsi_buf, sizeof(SRB_IO_CONTROL) + SENDIDLENGTH))
	{
		SENDCMDOUTPARAMS* pOut =
			(SENDCMDOUTPARAMS*)(scsi_buf + sizeof(SRB_IO_CONTROL));
		IDSECTOR* pId = (IDSECTOR*)(pOut->bBuffer);

		DWORD diskdata[256];
		int ijk = 0;
		USHORT* pIdSector = (USHORT*)pId;

		for (ijk = 0; ijk < 256; ijk++)
			diskdata[ijk] = pIdSector[ijk];

		char serial[100] = { 0 };
		ConvertToString(diskdata, 10, 19, serial);

		print_serial(serial);
	}
}