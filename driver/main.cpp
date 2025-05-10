#include <ntifs.h>
#include <ntddk.h>
#include "dbglog.hpp"
#include "windefs.hpp"
#include "globals.hpp"
#include "piddb.hpp"
#include "util.hpp"
#include "pattern_scanner.hpp"
#include "imports.hpp"
#include "native_imports.hpp"
#include "hash.hpp"
#include "sk_crypter.hpp"
#include "globals.hpp"
#include "spoofer.hpp"

#include <ntdef.h>
#include <intrin.h>

extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT * driver_obj, PUNICODE_STRING reg_path);
extern "C" void DriverUnload(PVOID driver_obj);
extern "C" NTSTATUS MappedEntry(globals * glob, PVOID reserved);


// 48 8B 1D ?? ?? ?? ?? EB ?? 83 7B 40
PSINGLE_LIST_ENTRY g_KernelHashBucketList = NULL;
PERESOURCE g_HashCacheLock = NULL;

typedef struct _HashBucketEntry
{
	struct _HashBucketEntry* Next;
	UNICODE_STRING DriverName;
	ULONG CertHash[5];
} HashBucketEntry, * PHashBucketEntry;

bool ClearHashBucketList(const wchar_t* driverName)
{
	util::module ci_dll;
	if (!util::get_module(skCrypt("ci.dll"), ci_dll) && !util::get_module(skCrypt("CI.dll"), ci_dll))
	{
		LOG("failed to grab ci.dll");
		return false;
	}

	LOG("ci.dll: %llx, %x", ci_dll.base, ci_dll.size);

	g_KernelHashBucketList = (PSINGLE_LIST_ENTRY)(ci_dll.base + globals::instance().args.g_KernelHashBucketList);
	g_HashCacheLock = (PERESOURCE)(ci_dll.base + globals::instance().args.g_HashCacheLock);

	LOG("g_KernelHashBucketList: %llx, g_HashCacheLock: %llx", g_KernelHashBucketList, g_HashCacheLock);

	if (!g_KernelHashBucketList || !g_HashCacheLock)
		return false;

	CALL_NO_RET(ExEnterCriticalRegionAndAcquireResourceExclusive, g_HashCacheLock);
	UINT32 removedCount = 0;

	for (PSINGLE_LIST_ENTRY link = g_KernelHashBucketList->Next, oldlink = g_KernelHashBucketList; link; oldlink = link, link = link->Next) {
		PHashBucketEntry entry = reinterpret_cast<PHashBucketEntry>(link);
		//LOG("name: %ws", entry->DriverName.Buffer);
		if (entry) {
			bool result;
			CALL_RET(result, wcsstr, entry->DriverName.Buffer, driverName);
			if (result)
			{
				LOG("driver is deleted from hashbucket %ws [%0X]", entry->DriverName.Buffer, entry->CertHash[0]);
				if (oldlink) {
					oldlink->Next = link->Next;
					link = link->Next;
				}

				CALL_NO_RET(ExFreePoolWithTag, entry, 0ul);
				removedCount++;
			}
		}
	}

	CALL_NO_RET(ExReleaseResourceAndLeaveCriticalRegion, g_HashCacheLock);
	return (removedCount > 0);
}

NTSTATUS open_key(PHANDLE regHandle, PUNICODE_STRING name, ACCESS_MASK access)
{
	NTSTATUS status = STATUS_SUCCESS;

	OBJECT_ATTRIBUTES objAttributes;
	InitializeObjectAttributes(&objAttributes, name, OBJ_CASE_INSENSITIVE, NULL, NULL);
	CALL_RET(status, ZwOpenKey, regHandle, access, &objAttributes);

	return status;
}
#define KEY_DEFAULT_SIZE ((sizeof(KEY_VALUE_FULL_INFORMATION) + sizeof(ULONG)) + 255)
NTSTATUS query_binary(HANDLE regKey, PUNICODE_STRING name, UINT8** data, ULONG* dataLength)
{
	*data = nullptr;
	*dataLength = 0;

	UCHAR buffer[KEY_DEFAULT_SIZE];
	PKEY_VALUE_FULL_INFORMATION kvInfo = (PKEY_VALUE_FULL_INFORMATION)buffer;;

	ULONG requestLength = KEY_DEFAULT_SIZE;
	ULONG resultLength = 0;

	NTSTATUS status = STATUS_SUCCESS;

	while (1) {

		CALL_RET(status, ZwQueryValueKey, regKey,
			name,
			KeyValueFullInformation,
			kvInfo,
			requestLength,
			&resultLength);

		NT_ASSERT(status != STATUS_BUFFER_OVERFLOW);

		if (status == STATUS_BUFFER_OVERFLOW) {

			if (kvInfo != (PKEY_VALUE_FULL_INFORMATION)buffer) {

				CALL_NO_RET(ExFreePoolWithTag, kvInfo, 0ul);
			}

			requestLength += 256;

			PVOID tbuf = NULL;
			CALL_RET(tbuf, ExAllocatePool, PagedPool, requestLength);
			kvInfo = (PKEY_VALUE_FULL_INFORMATION)tbuf;

			if (!kvInfo) {
				return STATUS_BUFFER_OVERFLOW;
			}

		}
		else {

			break;
		}
	}

	if (NT_SUCCESS(status))
	{
		if (kvInfo->DataLength > 0)
		{
			UINT8* regValue = (UINT8*)((PCHAR)kvInfo + kvInfo->DataOffset);
			PVOID tregbuf = NULL;
			CALL_RET(tregbuf, ExAllocatePool, PagedPool, kvInfo->DataLength);
			*data = (UINT8*)tregbuf;

			if (!*data)
				return STATUS_NO_MEMORY;

			*dataLength = kvInfo->DataLength;

			memcpy(*data, regValue, kvInfo->DataLength);

			if (kvInfo != (PKEY_VALUE_FULL_INFORMATION)buffer) {
				CALL_NO_RET(ExFreePoolWithTag, kvInfo, 0ul);
			}

			return status;
		}

		status = STATUS_INFO_LENGTH_MISMATCH;
	}

	if (kvInfo != (PKEY_VALUE_FULL_INFORMATION)buffer) {
		CALL_NO_RET(ExFreePoolWithTag, kvInfo, 0ul);
	}
	return status;
}
bool read_init_data(PUNICODE_STRING registry_path)
{
	bool result = false;

	HANDLE drv_key = NULL;
	if (NT_SUCCESS(open_key(&drv_key, registry_path, KEY_ALL_ACCESS)))
	{
		UNICODE_STRING data_name;
		CALL_NO_RET(RtlInitUnicodeString, &data_name, skCrypt(L"data"));
		UINT8* data = 0;
		ULONG data_length = 0;
		if (NT_SUCCESS(query_binary(drv_key, &data_name, &data, &data_length)))
		{
			if (data_length >= sizeof(driver_args_t))
			{
				auto tmp_args = (driver_args_t*)data;				
				memcpy(&globals::instance().args, tmp_args, sizeof(driver_args_t));

				CALL_NO_RET(ZwDeleteValueKey, drv_key, &data_name);
				CALL_NO_RET(ZwClose, drv_key);

				result = true;
			}

			CALL_NO_RET(ExFreePoolWithTag, data, 0ul);
			return result;
		}

		CALL_NO_RET(ZwDeleteValueKey, drv_key, &data_name);
		CALL_NO_RET(ZwClose, drv_key);
	}
	return result;
}

__forceinline wchar_t locase_w(wchar_t c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}

__forceinline int _strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
	wchar_t c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return -1;

	if (s2 == 0)
		return 1;

	do {
		c1 = locase_w(*s1);
		c2 = locase_w(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (int)(c1 - c2);
}

PVOID GetKernelBase(PDRIVER_OBJECT DriverObject)
{
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	PLDR_DATA_TABLE_ENTRY first = entry;
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
	{
		if (_strcmpi_w(entry->BaseDllName.Buffer, skCrypt(L"ntoskrnl.exe")) == 0)
			return entry->DllBase;
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
	return nullptr;
}

NTSTATUS DriverEntry(DRIVER_OBJECT* driver_obj, PUNICODE_STRING reg_path)
{
	// resolve ntoskrnl
	//auto ntos = (uintptr_t)GetKernelBase(driver_obj);
	util::module ntos_mod;
	util::_get_module(skCrypt("ntoskrnl.exe"), ntos_mod);
	auto ntos = ntos_mod.base;

	if (!ntos || !imports::init(ntos))
		return NTOS_IMPORT_ERROR;
	
	const auto& entry = (PLDR_DATA_TABLE_ENTRY)driver_obj->DriverSection;
	
	auto& glob = globals::instance();
	glob.driver_base = (UINT64)entry->DllBase;
	glob.driver_size = entry->SizeOfImage;
	glob.driver_name = entry->BaseDllName;

	LOG("%llx, %x, %wZ", glob.driver_base,
		glob.driver_size, &glob.driver_name);

	if (!read_init_data(reg_path))
	{
		LOG("FATAL: INIT DATA NOT FOUND");
		return INIT_DATA_ERROR;
	}
	
	LOG("%-40s = 0x%08X", "MmAllocateIndependentPages", glob.args.MmAllocateIndependentPages);
	LOG("%-40s = 0x%08X", "PiDDBLock", glob.args.PiDDBLock);
	LOG("%-40s = 0x%08X", "PiDDBCacheTable", glob.args.PiDDBCacheTable);
	LOG("%-40s = 0x%08X", "DirectoryTableBase", glob.args.DirectoryTableBase);
	LOG("%-40s = 0x%08X", "UserDirectoryTableBase", glob.args.UserDirectoryTableBase);
	//LOG("%-40s = 0x%08X", "KThreadMiscFlags", glob.args.KThreadMiscFlags);
	LOG("%-40s = 0x%08X", "g_KernelHashBucketList", glob.args.g_KernelHashBucketList);
	LOG("%-40s = 0x%08X", "g_HashCacheLock", glob.args.g_HashCacheLock);
	//LOG("%-40s = 0x%08X", "GetWindowProp", glob.args.GetWindowProp);
	//LOG("%-40s = 0x%08X", "KThreadTrapFrame", glob.args.KThreadTrapFrame);
	//LOG("%-40s = 0x%08X", "g_AslLogPfnVPrintf", glob.args.AslLogPfnVPrintf);

	// debugging....
	//while ( true )
	//{
	//	SLEEP( 1 );
	//}


	// 
	// PiDDB Cleanup
	auto _piddb = piddb::instance();
	if (!_piddb.init())
	{
		LOG("FATAL: PIDDB init failed");
		return PIDDB_INIT_ERROR;
	}

	if (!_piddb.clean())
	{
		LOG("FATAL: PIDDB clean failed");
		return PIDDB_CLEAN_ERROR;
	}

	LOG("PIDDB Cleanup done");

	//
	//
	if (!ClearHashBucketList(glob.driver_name.Buffer))
	{
		LOG("Failed to clear hash bucket list");
		return HASHBUCKET_ERROR;
	}

	
	LOG("ClearHashBucketList done");

	// 
	// BOOM!
	auto driver_status = spoofer::spoof();
	if (driver_status != SUCCESS)
	{
		LOG("spoofer::spoof failed with %llx", driver_status);
	}

	//
	// zZZZZZZZZzzZZZZ
	LOG( "Driver unloading..." );

	//
	// Better stealthy than sorry
	entry->FullDllName.Length = 0;
	entry->BaseDllName.Length = 0;

	// debugging....
	//while ( true )
	//{
	//	SLEEP( 1 );
	//}

	return driver_status;
}
