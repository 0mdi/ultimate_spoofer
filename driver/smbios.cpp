#include <ntifs.h>
#include "smbios.hpp"
#include "dbglog.hpp"
#include "util.hpp"
#include "pattern_scanner.hpp"
#include "sk_crypter.hpp"

// ------------------------------------------------
// SMBIOS / gnu-efi
// ------------------------------------------------

typedef struct
{
	UINT8   Type;
	UINT8   Length;
	UINT8   Handle[2];
} SMBIOS_HEADER;

typedef UINT8   SMBIOS_STRING;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING   Vendor;
	SMBIOS_STRING   BiosVersion;
	UINT8           BiosSegment[2];
	SMBIOS_STRING   BiosReleaseDate;
	UINT8           BiosSize;
	UINT8           BiosCharacteristics[8];
} SMBIOS_TYPE0;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING   Manufacturer;
	SMBIOS_STRING   ProductName;
	SMBIOS_STRING   Version;
	SMBIOS_STRING   SerialNumber;

	//
	// always byte copy this data to prevent alignment faults!
	//
	GUID			Uuid; // EFI_GUID == GUID?

	UINT8           WakeUpType;
} SMBIOS_TYPE1;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING   Manufacturer;
	SMBIOS_STRING   ProductName;
	SMBIOS_STRING   Version;
	SMBIOS_STRING   SerialNumber;
} SMBIOS_TYPE2;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING   Manufacturer;
	UINT8           Type;
	SMBIOS_STRING   Version;
	SMBIOS_STRING   SerialNumber;
	SMBIOS_STRING   AssetTag;
	UINT8           BootupState;
	UINT8           PowerSupplyState;
	UINT8           ThermalState;
	UINT8           SecurityStatus;
	UINT8           OemDefined[4];
} SMBIOS_TYPE3;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	UINT8           Socket;
	UINT8           ProcessorType;
	UINT8           ProcessorFamily;
	SMBIOS_STRING   ProcessorManufacture;
	UINT8           ProcessorId[8];
	SMBIOS_STRING   ProcessorVersion;
	UINT8           Voltage;
	UINT8           ExternalClock[2];
	UINT8           MaxSpeed[2];
	UINT8           CurrentSpeed[2];
	UINT8           Status;
	UINT8           ProcessorUpgrade;
	UINT8           L1CacheHandle[2];
	UINT8           L2CacheHandle[2];
	UINT8           L3CacheHandle[2];
} SMBIOS_TYPE4;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	uint16_t PhysicalArrayHandle;
	uint16_t ErrorInformationHandle;
	uint16_t TotalWidth;
	uint16_t DataWidth;
	uint16_t Size;
	uint8_t FormFactor;
	uint8_t DeviceSet;
	SMBIOS_STRING DeviceLocator;
	SMBIOS_STRING BankLocator;
	uint8_t MemoryType;
	uint16_t TypeDetail;
	// 2.3+
	uint16_t Speed;
	SMBIOS_STRING Manufacturer;
	SMBIOS_STRING SerialNumber;
	SMBIOS_STRING AssetTagNumber;
	SMBIOS_STRING PartNumber;
	// 2.6+
	uint8_t Attributes;
	// 2.7+
	uint32_t ExtendedSize;
	uint16_t ConfiguredClockSpeed;
	// 2.8+
	uint16_t MinimumVoltage;
	uint16_t MaximumVoltage;
	uint16_t ConfiguredVoltage;
} SMBIOS_TYPE17;

typedef union
{
	SMBIOS_HEADER* Hdr;
	SMBIOS_TYPE0* Type0;
	SMBIOS_TYPE1* Type1;
	SMBIOS_TYPE2* Type2;
	SMBIOS_TYPE3* Type3;
	SMBIOS_TYPE4* Type4;
	UINT8* Raw;
} SMBIOS_STRUCTURE_POINTER;

typedef struct
{
	UINT8   AnchorString[4];
	UINT8   EntryPointStructureChecksum;
	UINT8   EntryPointLength;
	UINT8   MajorVersion;
	UINT8   MinorVersion;
	UINT16  MaxStructureSize;
	UINT8   EntryPointRevision;
	UINT8   FormattedArea[5];
	UINT8   IntermediateAnchorString[5];
	UINT8   IntermediateChecksum;
	UINT16  TableLength;
	UINT32  TableAddress;
	UINT16  NumberOfSmbiosStructures;
	UINT8   SmbiosBcdRevision;
} SMBIOS_STRUCTURE_TABLE;

typedef struct _RAW_SMBIOS
{
	UINT8	Unknown;
	UINT8	MajorVersion;
	UINT8	MinorVersion;
	UINT8	DmiRevision;
	UINT32	Size;
	UINT8* Entry;
} RAW_SMBIOS;

namespace spoofer::smbios
{
	void RandomText(char* text, const int length)
	{
		if (!text)
			return;

		static const char alphanum[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

		ULONG seed = 0x12345678;
		CALL_RET(seed, KeQueryTimeIncrement);

		for (auto n = 0; n <= length; n++)
		{
			ULONG rnd;
			CALL_RET(rnd, RtlRandomEx, &seed);
			auto key = rnd % static_cast<int>(sizeof(alphanum) - 1);
			text[n] = alphanum[key];
		}
	}

	/**
 * \brief Get's the string from SMBIOS table
 * \param header Table header
 * \param string String itself
 * \return Pointer to the null terminated string
 */
	char* GetString(SMBIOS_HEADER* header, SMBIOS_STRING string)
	{
		const auto* start = reinterpret_cast<const char*>(header) + header->Length;

		if (!string || *start == 0)
			return nullptr;

		while (--string)
		{
			start += strlen(start) + 1;
		}

		return const_cast<char*>(start);
	}

	/**
	 * \brief Replace string at a given location by randomized string with same length
	 * \param string Pointer to string (has to be null terminated)
	 */
	void SpoofString(char* string)
	{
		const auto length = static_cast<int>(strlen(string));

		char* buffer = nullptr;
		CALL_RET(buffer, ExAllocatePool, NonPagedPool, length);
		//RandomText(buffer, length);
		for (int i = 0u; i < length; ++i)
		{
			buffer[i] = ((string[i] ^ globals::instance().args.SpoofHash[i % 16]) % 26) + 65;
		}

		buffer[length] = '\0';

		memcpy(string, buffer, length);

		CALL_NO_RET(ExFreePoolWithTag, buffer, 0);
	}

	void SpoofGUID(GUID* guid)
	{
		ULONG seed;
		CALL_RET(seed, KeQueryTimeIncrement);

		for (auto n = 0; n < sizeof(GUID); n++)
		{
			//ULONG rnd;
			//CALL_RET(rnd, RtlRandomEx, &seed);
			//auto key = rnd % 0xFF;
			*(uint8_t*)((uint64_t)guid + n) ^= globals::instance().args.SpoofHash[n % 16];
		}
	}

	/**
	 * \brief Modify information in the table of given header
	 * \param header Table header (only 0-3 implemented)
	 * \return
	 */
	NTSTATUS ProcessTable(SMBIOS_HEADER* header)
	{
		if (!header->Length)
			return STATUS_UNSUCCESSFUL;
		LOG("Smbios Type: %i", header->Type);

		if (header->Type == 0)
		{
			auto* type0 = reinterpret_cast<SMBIOS_TYPE0*>(header);

			auto* vendor = GetString(header, type0->Vendor);
			//RandomizeString(vendor);
			LOG("%s: type0, vendor: %s", __FUNCTION__, vendor);
		}
		else if (header->Type == 1)
		{
			auto* type1 = reinterpret_cast<SMBIOS_TYPE1*>(header);

			auto* manufacturer = GetString(header, type1->Manufacturer);
			//RandomizeString(manufacturer);

			auto* productName = GetString(header, type1->ProductName);
			//RandomizeString(productName);

			auto* serialNumber = GetString(header, type1->SerialNumber);
			LOG("%s: type1, manufacturer: %s, productName: %s, serialNumber: %s", __FUNCTION__, manufacturer, productName, serialNumber);
			SpoofString(serialNumber);
			LOG("spoofed to %s", serialNumber);

			LOG("%s: real guid: %llx, %llx", __FUNCTION__, *(uint64_t*)(&type1->Uuid), *(uint64_t*)((uint64_t)&type1->Uuid + 8));
			SpoofGUID(&type1->Uuid);
			LOG("%s: spoofed guid: %llx, %llx", __FUNCTION__, *(uint64_t*)(&type1->Uuid), *(uint64_t*)((uint64_t)&type1->Uuid + 8));
		}
		else if (header->Type == 2)
		{
			auto* type2 = reinterpret_cast<SMBIOS_TYPE2*>(header);

			auto* manufacturer = GetString(header, type2->Manufacturer);
			//RandomizeString(manufacturer);

			auto* productName = GetString(header, type2->ProductName);
			//RandomizeString(productName);

			auto* serialNumber = GetString(header, type2->SerialNumber);
			LOG("%s: type2, manufacturer: %s, productName: %s, serialNumber: %s", __FUNCTION__, manufacturer, productName, serialNumber);
			SpoofString(serialNumber);
			LOG("spoofed to %s", serialNumber);
		}
		else if (header->Type == 3)
		{
			auto* type3 = reinterpret_cast<SMBIOS_TYPE3*>(header);

			auto* manufacturer = GetString(header, type3->Manufacturer);
			//RandomizeString(manufacturer);

			auto* serialNumber = GetString(header, type3->SerialNumber);
			LOG("%s: type1, manufacturer: %s, serialNumber: %s", __FUNCTION__, manufacturer, serialNumber);
			SpoofString(serialNumber);
			LOG("spoofed to %s", serialNumber);

		}
		else if (header->Type == 4)
		{
			auto* type4 = reinterpret_cast<SMBIOS_TYPE4*>(header);
			
			LOG("%s: TYPE4: processorId: %llx", *(uint64_t*)(type4->ProcessorId));

			ULONG seed;
			CALL_RET(seed, KeQueryTimeIncrement);

			// randomize processorid
			for (uint8_t i = 0; i < sizeof(type4->ProcessorId); ++i)
			{
				//ULONG rnd;
				//CALL_RET(rnd, RtlRandomEx, &seed);
				type4->ProcessorId[i] ^= globals::instance().args.SpoofHash[i % 16];
			}
		}
		else if (header->Type == 17)
		{
			auto* type17 = (SMBIOS_TYPE17*)(header);

			/*
				SMBIOS_STRING Manufacturer;
	SMBIOS_STRING SerialNumber;
	SMBIOS_STRING AssetTagNumber;
	SMBIOS_STRING PartNumber;
		SMBIOS_STRING DeviceLocator;
	SMBIOS_STRING BankLocator;
			*/
			auto* deviceLocator = GetString(header, type17->DeviceLocator);
			if (deviceLocator)
			{
				LOG("%s: TYPE17: DeviceLocator: %s", __FUNCTION__, deviceLocator);
			}

			auto* bankLocator = GetString(header, type17->BankLocator);
			if (bankLocator)
			{
				LOG("%s: TYPE17: BankLocator: %s", __FUNCTION__, bankLocator);
			}

			if (type17->Manufacturer)
			{
				auto* manufacturer = GetString(header, type17->Manufacturer - 1);
				if (manufacturer)
				{
					LOG("%s: TYPE17: Manufacturer: %s", __FUNCTION__, manufacturer);
					//RandomizeString(manufacturer);
					//LOG("%s: TYPE17 (SPOOFED): Manufacturer: %s", __FUNCTION__, manufacturer);
				}
			}

			if (type17->AssetTagNumber)
			{
				auto* assettagnumber = GetString(header, type17->AssetTagNumber - 1);
				if (assettagnumber)
				{
					LOG("%s: TYPE17: AssetTagNumber: %s", __FUNCTION__, assettagnumber);
					SpoofString(assettagnumber);
					LOG("%s: TYPE17 (SPOOFED): AssetTagNumber: %s", __FUNCTION__, assettagnumber);
				}
			}

			if (type17->SerialNumber)
			{
				auto* serialNumber = GetString(header, type17->SerialNumber - 1);
				if (serialNumber)
				{
					LOG("%s: TYPE17: SerialNumber: %s", __FUNCTION__, serialNumber);
					SpoofString(serialNumber);
					LOG("%s: TYPE17 (SPOOFED): SerialNumber: %s", __FUNCTION__, serialNumber);
				}
			}

			//if (type17->AssetTagNumber)
			//{
			//	auto* partNumber = GetString(header, type17->AssetTagNumber);
			//	if (partNumber)
			//	{
			//		LOG("%s: TYPE17: PartNumber: %s", __FUNCTION__, partNumber);
			//		RandomizeString(partNumber);
			//		LOG("%s: TYPE17 (SPOOFED): PartNumber: %s", __FUNCTION__, partNumber);
			//	}
			//}

			//LOG("%s: TYPE17: SPOOFED SerialNumber: %s, PartNumber: %s", __FUNCTION__, serialNumber, partNumber);
		}

		return STATUS_SUCCESS;
	}

	/**
	 * \brief Loop through SMBIOS tables with provided first table header
	 * \param mapped Header of the first table
	 * \param size Size of all tables including strings
	 * \return
	 */
	NTSTATUS LoopTables(void* mapped, ULONG size)
	{
		auto* endAddress = static_cast<char*>(mapped) + size;
		while (true)
		{
			auto* header = static_cast<SMBIOS_HEADER*>(mapped);
			if (header->Type == 127 && header->Length == 4)
				break;

			ProcessTable(header);
			auto* end = static_cast<char*>(mapped) + header->Length;
			while (0 != (*end | *(end + 1))) end++;
			end += 2;
			if (end >= endAddress)
				break;

			mapped = end;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS RegistryWriteSMBIOS(void* mapped, ULONG size)
	{
		HANDLE KeyHandle = NULL;
		OBJECT_ATTRIBUTES ObjAttr;

		UNICODE_STRING uRegistryPath;
		CALL_NO_RET(RtlInitUnicodeString, &uRegistryPath, skCrypt(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data"));

		InitializeObjectAttributes(&ObjAttr,
			&uRegistryPath,
			OBJ_KERNEL_HANDLE,
			NULL, NULL);

		NTSTATUS Status;
		CALL_RET(Status, ZwOpenKey, &KeyHandle,
			KEY_ALL_ACCESS,
			&ObjAttr);

		if (NT_SUCCESS(Status))
		{
			//LOG("%s: Opened RegistryPath %ws\n", __FUNCTION__, RegistryPath);

			UNICODE_STRING uKeyName;
			CALL_NO_RET(RtlInitUnicodeString, &uKeyName, skCrypt(L"SMBiosData"));

			CALL_RET(Status, ZwSetValueKey, KeyHandle,
				&uKeyName,
				0,
				REG_BINARY,
				mapped,
				size);

			CALL_NO_RET(ZwClose, KeyHandle);
		}
		else
		{
			//LOG("%s: ZwOpenKey failed %X\n", __FUNCTION__, Status);
		}

		return Status;
	}

	/**
	 * \brief Find SMBIOS physical address, map it and then loop through
	 * table 0-3 and modify possible identifiable information
	 * \return Status of the change (will return STATUS_SUCCESS if mapping was successful)
	 */
	NTSTATUS spoof()
	{
		util::module ntos;
		if (!util::get_module(skCrypt("ntoskrnl.exe"), ntos))
		{
			LOG("Failed to find ntoskrnl.exe base!");
			return STATUS_UNSUCCESSFUL;
		}

		PATTERN_SET(ntos.base, ntos.size);
		auto* physicalAddress = (PPHYSICAL_ADDRESS)(PATTERN_FIND_CODE("\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15")); // WmipFindSMBiosStructure -> WmipSMBiosTablePhysicalAddress
		if (!physicalAddress)
		{
			LOG("Failed to find SMBIOS physical address!");
			return STATUS_UNSUCCESSFUL;
		}

		physicalAddress = reinterpret_cast<PPHYSICAL_ADDRESS>(reinterpret_cast<char*>(physicalAddress) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(physicalAddress) + 3));
		if (!physicalAddress)
		{
			LOG("Physical address is null!");
			return STATUS_UNSUCCESSFUL;
		}

		auto* sizeScan = (char*)PATTERN_FIND_CODE("\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B");  // WmipFindSMBiosStructure -> WmipSMBiosTableLength
		if (!sizeScan)
		{
			LOG("Failed to find SMBIOS size!");
			return STATUS_UNSUCCESSFUL;
		}

		const auto size = *reinterpret_cast<ULONG*>(static_cast<char*>(sizeScan) + 6 + *reinterpret_cast<int*>(static_cast<char*>(sizeScan) + 2));
		if (!size)
		{
			LOG("SMBIOS size is null!");
			return STATUS_UNSUCCESSFUL;
		}

		void* mapped = nullptr;
		CALL_RET(mapped, MmMapIoSpace, *physicalAddress, size, MmNonCached);
		if (!mapped)
		{
			LOG("Failed to map SMBIOS structures!");
			return STATUS_UNSUCCESSFUL;
		}

		LoopTables(mapped, size);


		// now write that into registry as well
		auto status = RegistryWriteSMBIOS(mapped, size);
		LOG("%s: registrywritesmbios: %x", __FUNCTION__, status);

		CALL_NO_RET(MmUnmapIoSpace, mapped, size);

		return STATUS_SUCCESS;
	}
}