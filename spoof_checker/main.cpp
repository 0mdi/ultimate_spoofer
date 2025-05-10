#include "ioctl_base.hpp"
#include "mac.hpp"
#include <iostream>
#include <ntddndis.h>
#include <strsafe.h>
#include <functional>
#include <NtDDNdis.h>
#include <IPTypes.h>
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "rpcrt4.lib")

#define  MAX_IDE_DRIVES  16

BOOL WINAPI GetPhyMacAddress(char* strServiceName)
{
	BOOL bRet = FALSE;
	char pstrBuf[512];
	wsprintfA(pstrBuf, "\\\\.\\%s", strServiceName);

	HANDLE hDev = CreateFileA(pstrBuf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
	if (hDev!= INVALID_HANDLE_VALUE)
	{
		int inBuf;
		BYTE outBuf[256] = { 0 };
		DWORD BytesReturned;
		inBuf = OID_802_3_PERMANENT_ADDRESS;

		if (DeviceIoControl(hDev, IOCTL_NDIS_QUERY_GLOBAL_STATS, (LPVOID)&inBuf, 4, outBuf, 256, &BytesReturned, NULL))
		{
			sprintf(pstrBuf, "Physical mac:% 02X-% 02X-% 02X-% 02X-% 02X-% 02X\n",
				outBuf[0], outBuf[1], outBuf[2], outBuf[3], outBuf[4], outBuf[5]);
			printf(pstrBuf);
			bRet = TRUE;
		}

		inBuf = OID_802_3_CURRENT_ADDRESS;
		if (DeviceIoControl(hDev, IOCTL_NDIS_QUERY_GLOBAL_STATS, (LPVOID)&inBuf, 4, outBuf, 256, &BytesReturned, NULL))
		{
			sprintf(pstrBuf, "Current mac:% 02X-% 02X-% 02X-% 02X-% 02X-% 02X\n",
				outBuf[0], outBuf[1], outBuf[2], outBuf[3], outBuf[4], outBuf[5]);
			printf(pstrBuf);
			bRet = TRUE;
		}
		CloseHandle(hDev);
	}
	return bRet;
}

//NIC MAC address
BOOL GetMacAddress()
{
	UINT uErrorCode = 0;
	PIP_ADAPTER_INFO pAda;
	ULONG uSize = 0;
	DWORD dwResult = GetAdaptersInfo(NULL, &uSize);

	if (dwResult == ERROR_BUFFER_OVERFLOW)
	{
		pAda = (PIP_ADAPTER_INFO) new BYTE[uSize];
		PIP_ADAPTER_INFO piai = pAda;
		dwResult = GetAdaptersInfo(piai, &uSize);
		if (ERROR_SUCCESS == dwResult)
		{
			while (piai)
			{
				printf("Name:% s\n", piai->AdapterName);
				printf("Description:% s\n", piai->Description);
				printf("Type:% d\n", piai->Type);
				GetPhyMacAddress(piai->AdapterName);
				printf("\n");
				piai = piai->Next;
			}
		}
		delete[] pAda;
	}
	return TRUE;
}

void mac_ioctl()
{
	GetMacAddress();
}

int main(int argc, char** argv)
{
	std::cout << "// PhysicalDrives..." << std::endl;
	for (int drive = 0; drive < MAX_IDE_DRIVES; ++drive)
	{
		char drive_name[256] = { 0 };
		sprintf_s(drive_name, "\\\\.\\PhysicalDrive%d", drive);

		auto drive_handle = CreateFileA(drive_name,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);

		if (drive_handle != INVALID_HANDLE_VALUE)
		{
			std::cout << "# DRIVE " << drive << std::endl;

			smart_rcv_drive_data smart_ioctl(drive_handle);
			smart_ioctl.trigger();

			storage_query_property storage_query_ioctl(drive_handle);
			storage_query_ioctl.trigger();

			scsi_miniport scsi_miniport_ioctl(drive_handle, drive);
			scsi_miniport_ioctl.trigger();
			
			ata_pass_through ata_pass_through_ioctl(drive_handle);
			ata_pass_through_ioctl.trigger();

			CloseHandle(drive_handle);
		}

	}

	std::cout << "// SCSI..." << std::endl;
	for (int drive = 0; drive < MAX_IDE_DRIVES; ++drive)
	{
		char drive_name[256] = { 0 };
		sprintf_s(drive_name, "\\\\.\\scsi%d", drive);

		auto drive_handle = CreateFileA(drive_name,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);

		if (drive_handle != INVALID_HANDLE_VALUE)
		{
			std::cout << "# DRIVE " << drive << std::endl;

			smart_rcv_drive_data smart_ioctl(drive_handle);
			smart_ioctl.trigger();

			storage_query_property storage_query_ioctl(drive_handle);
			storage_query_ioctl.trigger();

			scsi_miniport scsi_miniport_ioctl(drive_handle, drive);
			scsi_miniport_ioctl.trigger();

			ata_pass_through ata_pass_through_ioctl(drive_handle);
			ata_pass_through_ioctl.trigger();

			CloseHandle(drive_handle);
		}

	}

	std::cout << "// MAC" << std::endl;
	for (auto& mac : get_macs())
	{
		std::cout << "# MAC: " << mac << std::endl;
	}

	std::cout << "# ROUTER MAC: " << get_router_mac() << std::endl;

	std::cout << "// MAC IOCTL" << std::endl;
	mac_ioctl();


	std::cout << "done" << std::endl;
	std::cin.get();

	return 0;
}