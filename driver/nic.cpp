#include "nic.hpp"
#include "util.hpp"
#include "sk_crypter.hpp"
#include "stealthmem.hpp"
#include "pattern_scanner.hpp"
#include "dbglog.hpp"
#include "spoofer.hpp"
#include "imports.hpp"
#include "hash.hpp"

#include "../driver_shellcode/kernel_context.hpp"

#include "shellcode/NicControlHook.hpp"
#include "shellcode/nic_ioc.hpp"
#include "shellcode/nsi_ioc.hpp"
#include "shellcode/NsiEnumerateObjectsAllParametersExHook.hpp"
#include "shellcode/NsiControlHook.hpp"

#include <ntstrsafe.h>
//#include <ndis.h>


#include <pshpack1.h>
// dt ndis!_IF_PHYSICAL_ADDRESS_LH
typedef struct _IF_PHYSICAL_ADDRESS_LH {
	uint16_t Length;
	uint8_t Address[32];
} IF_PHYSICAL_ADDRESS_LH;

// dt ndis!_NDIS_IF_BLOCK
typedef struct _NDIS_IF_BLOCK {
	char _padding_0[0x464];
	IF_PHYSICAL_ADDRESS_LH ifPhysAddress; // 0x464
	IF_PHYSICAL_ADDRESS_LH PermanentPhysAddress; // 0x486
} NDIS_IF_BLOCK, * PNDIS_IF_BLOCK;

typedef struct _KSTRING {
	char _padding_0[0x10];
	WCHAR Buffer[1]; // 0x10 at least
} KSTRING, * PKSTRING;

typedef struct _NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES {
	char pad[0x5c];
	uint16_t MacAddressLength; //0x5c
	unsigned char PermanentMacAddress[32]; // 0x5e
	unsigned char CurrentMacAddress[32]; // 0x7e
}NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES, *PNDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;

typedef struct _NDIS_MINIPORT_BLOCK {
	char _pad[0xa98];
	PNDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES GeneralAttributes; // 0xa98
} NDIS_MINIPORT_BLOCK, *PNDIS_MINIPORT_BLOCK;

// dt ndis!_NDIS_FILTER_BLOCK
typedef struct _NDIS_FILTER_BLOCK {
	char _padding_0[0x8];
	struct _NDIS_FILTER_BLOCK* NextFilter; // 0x8
	char _padding_1[0x10];
	PNDIS_MINIPORT_BLOCK Miniport; // 0x20
	PKSTRING FilterInstanceName; // 0x28
	char _padding_2[0x40];
	struct _NDIS_FILTER_BLOCK* GlobalFilter; // 0x68
	struct _NDIS_FILTER_BLOCK* LowerFilter; // 0x70
	struct _NDIS_FILTER_BLOCK* HigherFilter; // 0x78
} NDIS_FILTER_BLOCK, * PNDIS_FILTER_BLOCK;

typedef struct _SWAP {
	UNICODE_STRING Name;
	PVOID* Swap;
	PVOID Original;
} SWAP, * PSWAP;

typedef struct _SWAPPTR {
	SWAP Buffer[0xFF];
	ULONG Length;
} SWAPPTR;

typedef struct _NIC_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
	PDRIVER_DISPATCH PnpOriginal;
} NIC_DRIVER, * PNIC_DRIVER;

typedef struct _NIC_STRUCT {
	uint32_t Length;
	NIC_DRIVER Drivers[0xFF];
} NIC_STRUCT;
#include <poppack.h>

extern "C"
{
	extern POBJECT_TYPE* IoDriverObjectType;
}

kernel_context* ctx = nullptr;

// Appends swap to swap list
#define AppendSwap(name, swap, hook, original) { \
	UNICODE_STRING _n = name; \
	*(PVOID *)&original = InterlockedExchangePointer((PVOID *)(swap), (PVOID)hook); \
	LOG("swapped %wZ", &_n); \
}

static PVOID SafeCopy(PVOID src, uint32_t size) {
	PCHAR buffer = (PCHAR)ExAllocatePool(NonPagedPool, size);
	if (buffer) {
		MM_COPY_ADDRESS addr = { 0 };
		addr.VirtualAddress = src;

		SIZE_T read = 0;
		if (NT_SUCCESS(MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_VIRTUAL, &read)) && read == size) {
			return buffer;
		}

		ExFreePool(buffer);
	}
	else {
		LOG("! failed to allocate pool of size %d !", size);
	}

	return 0;
}

static PWCHAR TrimGUID(PWCHAR guid, uint32_t max) {
	uint32_t i = 0;
	PWCHAR start = guid;

	--max;
	for (; i < max && *start != L'{'; ++i, ++start);
	for (; i < max && guid[i++] != L'}';);

	guid[i] = 0;
	return start;
}


__forceinline void spoof_mac(uint8_t* buf, uint32_t len)
{
	if (len != 6)
	{
		LOG("len != 6: %i", len);
		return;
	}

	LOG("spoof_mac: (len: %i), MAC: %02X-%02X-%02X-%02X-%02X-%02X", len,
		buf[0], buf[1],
		buf[2], buf[3],
		buf[4], buf[5])


	auto ctx = (kernel_context*)spoofer::get_ctx();
	auto hash = fnva1_buffer(buf, len);
	for (uint16_t i = 0; i < ctx->mac_count; ++i)
	{
		if (ctx->mac_spoofed_hash_cache[i] == hash)
		{
			LOG("spoof_mac: mac already spoofed!");
			return;
		}
	}
	
	for (uint16_t i = 0; i < ctx->mac_count; ++i)
	{
		if (ctx->mac_hash_cache[i] == hash)
		{
			auto spoofed_mac = ctx->mac_spoofed_cache[i];
			memcpy(buf, spoofed_mac, len);
			
			LOG("spoof_mac: mac spoofed from cache!");
			LOG("NEW_MAC: %02X-%02X-%02X-%02X-%02X-%02X",
				buf[0], buf[1],
				buf[2], buf[3],
				buf[4], buf[5])
			return;
		}
	}

	//auto seed = hash ^ ctx->startup_time;
	uint8_t spoofed_mac[8] = { 0 };
	for (auto i = 0u; i < len; ++i)
	{
		//ULONG rnd = 0;
		//CALL_RET(rnd, RtlRandomEx, (ULONG*)&seed);
		spoofed_mac[i] = buf[i] ^ globals::instance().args.SpoofHash[i % 16];
	}

	// put into cache
	auto index = ctx->mac_count++;
	ctx->mac_hash_cache[index] = hash;
	for (auto i = 0u; i < len; ++i)
		ctx->mac_spoofed_cache[index][i] = spoofed_mac[i];
	ctx->mac_spoofed_hash_cache[index] = fnva1_buffer(spoofed_mac, len);

	//LOG("Spoof MAC: %llx -> %llx", *(uint64_t*)buf, *(uint64_t*)spoofed_mac);
	// and now overwrite
	memcpy(buf, spoofed_mac, len);
	LOG("NEW_MAC: %02X-%02X-%02X-%02X-%02X-%02X",
		buf[0], buf[1],
		buf[2], buf[3],
		buf[4], buf[5])
}

namespace spoofer::nic
{
	uint64_t ndisDummyIrpHandler = 0;

	void hook_filter(PNDIS_FILTER_BLOCK filter, NIC_STRUCT* NICs, uint64_t NICControl_shell, uint64_t CallbackThunk)
	{
		PWCHAR copy = (PWCHAR)SafeCopy(filter->FilterInstanceName->Buffer, 256);
		if (copy)
		{
			WCHAR adapter[256] = { 0 };
			_RtlStringCchPrintfW(adapter, 256, skCrypt(L"\\Device\\%ws"), TrimGUID(copy, 256 / 2));
			ExFreePool(copy);

			LOG("found NIC %ws", adapter);

			UNICODE_STRING name = { 0 };
			RtlInitUnicodeString(&name, adapter);

			PFILE_OBJECT file = 0;
			PDEVICE_OBJECT device = 0;

			if (NICs->Length < 0xFF)
			{
				// check if we can hook more drivers
				NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &file, &device);
				if (NT_SUCCESS(status))
				{
					// Now prepare for our 1337 abuse hook
					/*
					__int64 __fastcall KWorkItemBase<Ndis::BindEngine,KWorkItem<Ndis::BindEngine>>::CallbackThunk(__int64 a1, __int64 a2)
					{
						return (*(__int64 (__fastcall **)(_QWORD, __int64))(a1 + 0x28))(*(_QWORD *)(a1 + 0x20), a2);
					}
					+0x020 CurrentIrp       : Ptr64 _IRP
					+0x028 Timer            : Ptr64 _IO_TIMER

					*/
					LOG("Hooking DeviceObject: %llx Timer: %llx", device, device->Timer);
					device->Timer = (PIO_TIMER)NICControl_shell; // pray that this is stable
					*(uint8_t*)device->DeviceExtension = 0x12; // ok ^ causes bsod on shutdown, ppFix

					PDRIVER_OBJECT driver = device->DriverObject;
					if (driver)
					{
						BOOLEAN exists = FALSE;
						for (uint32_t i = 0; i < NICs->Length; ++i)
						{
							if (NICs->Drivers[i].DriverObject == driver)
							{
								exists = TRUE;
								break;
							}
						}

						if (exists)
						{
							LOG("%wZ already swapped", &driver->DriverName);
						}
						else
						{
							PNIC_DRIVER nic = &NICs->Drivers[NICs->Length];
							nic->DriverObject = driver;

							// 1337 hook
							AppendSwap(driver->DriverName, &driver->MajorFunction[IRP_MJ_DEVICE_CONTROL], CallbackThunk/*NICControl*//*NICControl_shell*//*ndisDummyIrpHandler*/, nic->Original);
							
							// also hook IRP_PNP so we can avoid BSOD on shutdown
							//AppendSwap(driver->DriverName, &driver->MajorFunction[IRP_MJ_PNP], CallbackThunk/*NICControl*//*NICControl_shell*//*ndisDummyIrpHandler*/, nic->PnpOriginal);

							++NICs->Length;
						}

						// Indirectly dereferences device object
						ObDereferenceObject(file);
					}
				}

			}
		}

	}

	DRIVER_STATUS spoof()
	{
		util::module ndis = { 0 };
		if (!util::get_module(skCrypt("ndis.sys"), ndis) && !util::get_module(skCrypt("NDIS.SYS"), ndis))
		{
			LOG("ndis.sys not found");
			return NDIS_NOT_FOUND;
		}

		// init context
		ctx = (kernel_context*)spoofer::get_ctx();
		ctx->mac_count = 0;
		CALL_RET(ctx->NicsPtr, ExAllocatePool, NonPagedPool, sizeof(NIC_STRUCT));
		memset((void*)ctx->NicsPtr, 0, sizeof(NIC_STRUCT));
		auto NICs = (NIC_STRUCT*)ctx->NicsPtr;

		PATTERN_SET(ndis.base, ndis.size);
		ndisDummyIrpHandler = PATTERN_FIND_OFS_CODE("\x48\x8D\x05\x00\x00\x00\x00\x8D\x4A\x9C", 3);
		if (!ndisDummyIrpHandler)
		{
			LOG("ndisDummyIrpHandler not found");
			return NDIS_DUMMY_NOT_FOUND;
		}

		LOG("ndisDummyIrpHandler: %llx", ndisDummyIrpHandler);

		//__int64 __fastcall KWorkItemBase<Ndis::BindEngine, KWorkItem<Ndis::BindEngine>>::CallbackThunk(__int64 a1, __int64 a2)
		/*
		sig: 48 83 EC 28 48 8B 41 28 
		adding references
		sig: \x48\x83\xEC\x28\x48\x8B\x41\x28, xxxxxxxx
		*/
		auto CallbackThunk = (uint64_t)PATTERN_FIND_CODE("\x48\x83\xEC\x28\x48\x8B\x41\x28");
		if (!CallbackThunk)
		{
			LOG("CallbackThunk not found");
			return NDIS_CALLBACK_THUNK_NOT_FOUND;
		}

		PNDIS_FILTER_BLOCK ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)PATTERN_FIND_CODE("\x40\x8A\xF0\x48\x8B\x05");
		if (!ndisGlobalFilterList)
			return NDIS_FILTER_NOT_FOUND;

		uint64_t* ndisFilter_IfBlock = (uint64_t*)PATTERN_FIND_CODE("\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33");
		if (!ndisFilter_IfBlock)
			return NDIS_FILTER_NOT_FOUND2;

		LOG("ndisFilter_IfBlock: %llx", ndisFilter_IfBlock);

		uint32_t ndisFilter_IfBlock_offset = *(uint32_t*)((uint8_t*)ndisFilter_IfBlock + 12);

		ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)((uint8_t*)ndisGlobalFilterList + 3);
		ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK*)((uint8_t*)ndisGlobalFilterList + 7 + *(uint32_t*)((uint8_t*)ndisGlobalFilterList + 3));

		LOG("ndisGlobalFilterList: %llx", ndisGlobalFilterList);

		// Allocate NICControl & nic_ioc
		uint64_t NICControl_shell = 0;
		{
			auto ptr = SHGetDecryptedNicControlHook();
			auto size = SHGetSizeNicControlHook();
			NICControl_shell = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!NICControl_shell)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)NICControl_shell, ptr, size);

			SHDestroyNicControlHook();

			auto shell_ctx = (uint64_t*)(NICControl_shell + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}
		uint64_t NsiControl_shell = 0;
		{
			auto ptr = SHGetDecryptedNsiControlHook();
			auto size = SHGetSizeNsiControlHook();
			NsiControl_shell = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!NsiControl_shell)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)NsiControl_shell, ptr, size);

			SHDestroyNsiControlHook();

			auto shell_ctx = (uint64_t*)(NsiControl_shell + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}
		uint64_t nic_ioc_shell = 0;
		{
			auto ptr = SHGetDecryptednic_ioc();
			auto size = SHGetSizenic_ioc();
			nic_ioc_shell = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!nic_ioc_shell)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)nic_ioc_shell, ptr, size);

			SHDestroynic_ioc();

			auto shell_ctx = (uint64_t*)(nic_ioc_shell + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}
		ctx->nic_ioc = nic_ioc_shell;

		uint64_t nsi_ioc_shell = 0;
		{
			auto ptr = SHGetDecryptednsi_ioc();
			auto size = SHGetSizensi_ioc();
			nsi_ioc_shell = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!nsi_ioc_shell)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)nsi_ioc_shell, ptr, size);

			SHDestroynsi_ioc();

			auto shell_ctx = (uint64_t*)(nsi_ioc_shell + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}
		ctx->nsi_ioc = nsi_ioc_shell;


		LOG("Handling NDIS adatpers...");
		uint32_t count = 0;
		for (PNDIS_FILTER_BLOCK filter = ndisGlobalFilterList; filter; filter = filter->NextFilter) 
		{
			LOG("filter: %llx, filter->NextFilter: %llx", filter, filter->NextFilter);
			PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK*)((uint8_t*)filter + ndisFilter_IfBlock_offset);
			if (block) 
			{
				hook_filter(filter, NICs, NICControl_shell, CallbackThunk);

				// Current MAC
				IF_PHYSICAL_ADDRESS_LH* addr = &block->ifPhysAddress;
				spoof_mac(addr->Address, addr->Length);
				// Permanent MAC
				addr = &block->PermanentPhysAddress;
				spoof_mac(addr->Address, addr->Length);
				++count;
			}

			if (filter->LowerFilter)
			{
				hook_filter(filter->LowerFilter, NICs, NICControl_shell, CallbackThunk);
				PNDIS_IF_BLOCK lower_block = *(PNDIS_IF_BLOCK*)((uint8_t*)filter->LowerFilter + ndisFilter_IfBlock_offset);
				if (lower_block)
				{
					// Current MAC
					IF_PHYSICAL_ADDRESS_LH* addr = &lower_block->ifPhysAddress;
					spoof_mac(addr->Address, addr->Length);
					// Permanent MAC
					addr = &lower_block->PermanentPhysAddress;
					spoof_mac(addr->Address, addr->Length);
					++count;
				}
			}

			if (filter->HigherFilter)
			{
				hook_filter(filter->HigherFilter, NICs, NICControl_shell, CallbackThunk);
				PNDIS_IF_BLOCK higher_block = *(PNDIS_IF_BLOCK*)((uint8_t*)filter->HigherFilter + ndisFilter_IfBlock_offset);
				if (higher_block)
				{
					// Current MAC
					IF_PHYSICAL_ADDRESS_LH* addr = &higher_block->ifPhysAddress;
					spoof_mac(addr->Address, addr->Length);
					// Permanent MAC
					addr = &higher_block->PermanentPhysAddress;
					spoof_mac(addr->Address, addr->Length);
					++count;
				}
			}
			
			if (filter->GlobalFilter)
			{
				hook_filter(filter->GlobalFilter, NICs, NICControl_shell, CallbackThunk);
				PNDIS_IF_BLOCK global_block = *(PNDIS_IF_BLOCK*)((uint8_t*)filter->GlobalFilter + ndisFilter_IfBlock_offset);
				if (global_block)
				{
					// Current MAC
					IF_PHYSICAL_ADDRESS_LH* addr = &global_block->ifPhysAddress;
					spoof_mac(addr->Address, addr->Length);
					// Permanent MAC
					addr = &global_block->PermanentPhysAddress;
					spoof_mac(addr->Address, addr->Length);
					++count;
				}
			}


			if (filter->Miniport)
			{
				LOG("filter->Miniport: %llx", filter->Miniport);

				auto attr = filter->Miniport->GeneralAttributes;
				if (attr)
				{
					LOG("filter->Miniport->GeneralAttributes: %llx", attr);

					spoof_mac(attr->PermanentMacAddress, attr->MacAddressLength);
					spoof_mac(attr->CurrentMacAddress, attr->MacAddressLength);
				}
			}
		}
		LOG("handled %d MACs", count);

		//LOG("Hooking Ndis.sys directly...");
		//{
		//	UNICODE_STRING driver_str;
		//	RtlInitUnicodeString(&driver_str, L"\\Driver\\ndis");

		//	PDRIVER_OBJECT driver_object = nullptr;
		//	NTSTATUS status;
		//	CALL_RET(status, ObReferenceObjectByName, &driver_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&driver_object);
		//	if (NT_SUCCESS(status))
		//	{
		//		//AppendSwap("ndis.sys", &driver->MajorFunction[IRP_MJ_DEVICE_CONTROL], NICControl_shell, nic->orig)
		//		PNIC_DRIVER nic = &NICs->Drivers[NICs->Length];
		//		nic->DriverObject = driver_object;

		//		// 1337 hook
		//		AppendSwap(driver_object->DriverName, &driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL], /*NICControl*/NICControl_shell/*ndisDummyIrpHandler*/, nic->Original);
		//		++NICs->Length;
		//		ObDereferenceObject(driver_object);
		//	}
		//	else
		//	{
		//		LOG("Could nopt open ndis: %llx", status);
		//	}
		//}

		util::module nsiproxy, netio;
		if (!util::get_module(skCrypt("nsiproxy.sys"), nsiproxy) && !util::get_module(skCrypt("NSIPROXY.SYS"), nsiproxy))
		{
			LOG("failed to get nsiproxy.sys");
			return NSI_PROXY_NOT_FOUND;
		}

		if (!util::get_module(skCrypt("netio.sys"), netio) && !util::get_module(skCrypt("NETIO.SYS"), netio))
		{
			LOG("failed to get netio.sys");
			return NSI_PROXY_NOT_FOUND;
		}

		// to make it look legit, we will abuse netio.sys!IPsecGwSetCallbackDispatch which is basically just a wrapper for our hook
		// HINT: IPsec* functions seem abusable af
		PATTERN_SET(netio.base, netio.size);
		auto IPsecGwSetCallbackDispatch = (uint64_t)PATTERN_FIND_CODE("\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06");
		if (!IPsecGwSetCallbackDispatch)
		{
			LOG("failed to get IPsecGwSetCallbackDispatch");
			return NETIO_PATTERN_NOT_FOUND;
		}

		uint64_t IPsecGwSetCallbackDispatchQword = *(uint32_t*)(IPsecGwSetCallbackDispatch + 7) + IPsecGwSetCallbackDispatch + 11;
		LOG("IPsecGwSetCallbackDispatchQword: %llx", IPsecGwSetCallbackDispatchQword);
	
		// Now prepare abuse gadget and overwrite irp handler
		//*(uint64_t*)IPsecGwSetCallbackDispatchQword = NsiControl_shell;

		//LOG("Hooking nsiproxy...");
		//{
		//	UNICODE_STRING driver_str;
		//	RtlInitUnicodeString(&driver_str, skCrypt(L"\\Driver\\nsiproxy"));

		//	PDRIVER_OBJECT driver_object = nullptr;
		//	NTSTATUS status;
		//	CALL_RET(status, ObReferenceObjectByName, &driver_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&driver_object);
		//	if (NT_SUCCESS(status))
		//	{

		//		// 1337 hook
		//		ctx->NsiControlOrig = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		//		driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)IPsecGwSetCallbackDispatch;

		//		LOG("nsiproxy hooked!");

		//		ObDereferenceObject(driver_object);
		//	}
		//	else
		//	{
		//		LOG("Could nopt open ndis: %llx", status);
		//	}
		//}
		

		LOG("done!");
		return SUCCESS;
	}
}