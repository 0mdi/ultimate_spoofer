#include "mac.hpp"

#include <Shlwapi.h>
#include <atlbase.h>
#include <Iphlpapi.h>
#include <setupapi.h>
#include <intsafe.h>
#include <ShlObj.h>
#include <algorithm> 
#include <cctype>
#include <locale>

std::vector<std::string> get_macs()
{
	std::vector<std::string> macs;

	PIP_ADAPTER_INFO AdapterInfo;


	char buffer[1000];

	DWORD dwBufLen = sizeof(AdapterInfo);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		return macs;
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen     variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {

		AdapterInfo = (IP_ADAPTER_INFO*)realloc(AdapterInfo, dwBufLen);
		if (AdapterInfo == NULL) {
			return macs;
		}
	}
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR)
	{
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info
		do
		{
			if (strstr(pAdapterInfo->Description, "VMware") == 0)
			{
				if (strstr(pAdapterInfo->Description, "TAP-Windows") == 0)
				{
					sprintf(buffer, "%02X-%02X-%02X-%02X-%02X-%02X",
						pAdapterInfo->Address[0], pAdapterInfo->Address[1],
						pAdapterInfo->Address[2], pAdapterInfo->Address[3],
						pAdapterInfo->Address[4], pAdapterInfo->Address[5]);


					macs.push_back(buffer);// picosha2::sha256str(buffer);
				}
			}
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
		free(AdapterInfo);

	}
	return macs;

}
std::string get_router_mac()
{
	PIP_ADAPTER_INFO adapters = nullptr;
	ULONG adapterTableSize = 0x1000;


	ULONG status = 0;
	do
	{
		if (adapters != nullptr)
			adapterTableSize += 0x1000;

		adapters = (PIP_ADAPTER_INFO)realloc(adapters, adapterTableSize);
		status = GetAdaptersInfo(adapters, &adapterTableSize);
	} while (status == ERROR_BUFFER_OVERFLOW);

	PIP_ADAPTER_INFO currentAdapter = adapters;
	while (currentAdapter)
	{
		if (strcmp(currentAdapter->GatewayList.IpAddress.String, "0.0.0.0") != 0)
		{
			PMIB_IPNETTABLE arpTable = nullptr;
			ULONG arpTableSize = 0x1000;

			status = 0;
			do
			{
				if (arpTable != nullptr)
					arpTableSize += 0x1000;

				arpTable = (PMIB_IPNETTABLE)realloc(arpTable, arpTableSize);
				status = GetIpNetTable(arpTable, &arpTableSize, TRUE);
			} while (status == ERROR_INSUFFICIENT_BUFFER);

			if (status == NO_ERROR)
			{
				for (int i = 0; i < arpTable->dwNumEntries; i++)
				{
					auto& arpEntry = arpTable->table[i];
					auto lAddr = inet_addr(currentAdapter->GatewayList.IpAddress.String);
					if (arpEntry.dwAddr == lAddr)
					{
						std::string routerMac;

						char szRouterMac[100];
						sprintf(szRouterMac, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", arpEntry.bPhysAddr[0],
							arpEntry.bPhysAddr[1], arpEntry.bPhysAddr[2], arpEntry.bPhysAddr[3], arpEntry.bPhysAddr[4], arpEntry.bPhysAddr[5]);

						if (adapters)
							free(adapters);

						if (arpTable)
							free(arpTable);

						return szRouterMac;
					}
				}
			}

			if (arpTable)
				free(arpTable);
		}
		currentAdapter = currentAdapter->Next;
	}

	if (adapters)
		free(adapters);

	return "";
}