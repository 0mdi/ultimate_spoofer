//#include <wdm.h>
#include "windef.hpp"
#include "hash.hpp"
#include "spinlock.hpp"
#include "kernel_context.hpp"
#include "inline_util.hpp"
#include "stack_string.hpp"

#define SHELLCODE_END_MARKER_MAGIC 0xB16B00B5B16B00B5
#define CONTEXT_DEFAULT_MAGIC_VALUE 0xDEAD1234DEADBEEF

// DISK
#define IOCTL_STORAGE_QUERY_PROPERTY 0x2D1400
#define IOCTL_ATA_PASS_THROUGH 0x4D02C
#define SMART_RCV_DRIVE_DATA 0x7C088
#define SMART_RCV_DRIVE_DATA_EX 0x7008C
#define IOCTL_DISK_GET_PARTITION_INFO_EX 0x70048
#define IOCTL_DISK_GET_DRIVE_LAYOUT_EX 0x70050
#define IOCTL_SCSI_MINIPORT 0x4D008
#define IOCTL_SCSI_MINIPORT_IDENTIFY 0x1B0501
#define IOCTL_SCSI_PASS_THROUGH_DIRECT 0x4d014

#define NVME_PASS_THROUGH_SRB_IO_CODE 0xe0002000
#define SCSI_VPD_UNIT_SERIAL_NUMBER     0x80
#define SCSI_VPD_DEVICE_IDENTIFICATION  0x83

// MAC
#define IOCTL_NDIS_QUERY_GLOBAL_STATS 0x170002
#define OID_802_3_PERMANENT_ADDRESS             0x01010101
#define OID_802_3_CURRENT_ADDRESS               0x01010102
#define OID_802_5_PERMANENT_ADDRESS             0x02010101
#define OID_802_5_CURRENT_ADDRESS               0x02010102
#define OID_WAN_PERMANENT_ADDRESS               0x04010101
#define OID_WAN_CURRENT_ADDRESS                 0x04010102
#define OID_ARCNET_PERMANENT_ADDRESS            0x06010101
#define OID_ARCNET_CURRENT_ADDRESS              0x06010102

#ifndef INQUIRY
#define INQUIRY 0x12
#endif

#define DBGPRINT 0

__forceinline bool is_hooked(uint64_t ptr)
{
	return (*(uint8_t*)ptr == 0xCC || ((*(uint16_t*)ptr == 0xB848 && *(uint16_t*)(ptr + 10) == 0xE0FF) || /*movabs rax, ?; jmp rax;*/
		(*(uint16_t*)ptr == 0xBB48 && *(uint16_t*)(ptr + 10) == 0xE3FF) || /*movabs rbx, ?; jmp rbx;*/
		(*(uint16_t*)ptr == 0xBA49 && *(uint16_t*)(ptr + 10) == 0x41FF) || /*movabs r10, ?; jmp r10;*/
		(*(uint16_t*)ptr == 0xBF48 && *(uint16_t*)(ptr + 10) == 0xE7FF) || /*movabs rdi, ?; jmp rdi;*/
		(*(uint16_t*)ptr == 0xBE48 && *(uint16_t*)(ptr + 10) == 0xE6FF) || /*movabs rsi, ?; jmp rsi;*/
		(*(uint16_t*)ptr == 0xB948 && *(uint16_t*)(ptr + 10) == 0xE1FF) || /*movabs rcx, ?; jmp rcx;*/
		(*(uint16_t*)ptr == 0xBA48 && *(uint16_t*)(ptr + 10) == 0xE2FF)) /*movabs rdx, ?; jmp rdx;*/);
}

#define CALL_RET(ret, fn, ...) {volatile auto _fn = (kernel_context::fn ## _t)((uint64_t)ctx->fn ^ ctx->xor_key); if (!is_hooked((uint64_t)_fn)){ret = (decltype(ret))_fn(__VA_ARGS__);}}
#define CALL_NRET(fn, ...) {volatile auto _fn = (kernel_context::fn ## _t)((uint64_t)ctx->fn ^ ctx->xor_key); if (!is_hooked((uint64_t)_fn)){_fn(__VA_ARGS__);}}


#if (DBGPRINT==1)
#define STACK_LOG(x, ...) {STACK_STRING(stack_str, x "\n"); CALL_NRET(DbgPrint, stack_str, __VA_ARGS__);}
#else
#define STACK_LOG(x, ...) 
#endif

//const STORAGE_PROPERTY_ID StorageAdapterProtocolSpecificProperty = (STORAGE_PROPERTY_ID)49;
//const STORAGE_PROPERTY_ID StorageDeviceProtocolSpecificProperty = (STORAGE_PROPERTY_ID)50;


typedef struct _IOC_REQUEST {
	kernel_context* ctx;
	PVOID Buffer;
	ULONG BufferLength;
	PVOID OldContext;
	PIO_COMPLETION_ROUTINE OldRoutine;
	STORAGE_PROPERTY_ID property_id;
} IOC_REQUEST, * PIOC_REQUEST;

typedef
NTSTATUS
DRIVER_DISPATCH(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
);

typedef DRIVER_DISPATCH* PDRIVER_DISPATCH;

#include <pshpack1.h>
typedef struct _NIC_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
	PDRIVER_DISPATCH PnpOriginal;
} NIC_DRIVER, * PNIC_DRIVER;

typedef struct _NIC_STRUCT {
	uint32_t Length;
	NIC_DRIVER Drivers[0xFF];
} NIC_STRUCT;

typedef struct _NSI_ENUMERATE_OBJECTS_ALL_PRAMETERS_EX {
	uint64_t Unknown1;
	ULONG Unknown2;
	ULONG __unused1;
	uint64_t Unknown3;
	ULONG Type;
	ULONG __unused2;
	ULONG Unknown4;
	ULONG Unknown5;
	uint64_t EntryPointer_1;
	ULONG EntrySize_1;
	ULONG __unused3;
	uint64_t EntryPointer_2;
	ULONG EntrySize_2;
	ULONG __unused4;
	uint64_t EntryPointer_3;
	ULONG EntrySize_3;
	ULONG __unused5;
	uint64_t EntryPointer_4;
	ULONG EntrySize_4;
	ULONG __unused6;
	ULONG Count;
	ULONG __unused7;
} NSI_ENUMERATE_OBJECTS_ALL_PRAMETERS_EX, * PNSI_ENUMERATE_OBJECTS_ALL_PRAMETERS_EX;

typedef struct _NSI_ADAPTER_INFO_ROW {
	UCHAR __unused1[0x224];
	USHORT MacAddressLength;
	UCHAR MacAddress[6];
} *PNSI_ADAPTERINFO_ROW;

struct _MDL
{
	_MDL* Next;
	uint16_t Size;
	uint16_t MdlFlags;
	uint16_t AllocationProcessorNumber;
	uint16_t Reserved;
	PVOID Process;
	uint64_t MappedSystemVa;
	uint64_t StartVa;
	uint32_t ByteCount;
	uint32_t ByteOffset;
};

//typedef struct _NSI_PARAMS {
//	char _padding_0[0x18];
//	ULONG Type; // 0x18
//} NSI_PARAMS, * PNSI_PARAMS;

struct NSI_PARAMS
{
	__int64 field_0;
	__int64 field_8;
	__int64 field_10;
	int Type;
	int field_1C;
	int field_20;
	int field_24;
	//char field_42;
	__int64 AddrTable;
	int AddrEntrySize;
	int field_34;
	__int64 NeighborTable;
	int NeighborTableEntrySize;
	int field_44;
	__int64 StateTable;
	int StateTableEntrySize;
	int field_54;
	__int64 OwnerTable;
	int OwnerTableEntrySize;
	int field_64;
	int Count;
	int field_6C;
};

constexpr auto kVal = sizeof(NSI_PARAMS);

#include <poppack.h>

#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define NSI_PARAMS_ARP (11)

__forceinline bool is_generated_serial(kernel_context* ctx, hash32_t serial_hash)
{
	for (uint16_t i = 0; i < ctx->subserial_count; ++i)
	{
		if (ctx->rndsubserial_hashes[i] == serial_hash)
			return true;
	}
	return false;
}

__forceinline char* get_spoofed_cache(kernel_context* ctx, hash32_t serial_hash)
{
	for (uint16_t i = 0; i < ctx->subserial_count; ++i)
	{
		if (ctx->subserial_cache[i] == serial_hash)
			return ctx->rndsubserial_cache[i];
	}
	return nullptr;
}

__forceinline void randomize_subserial(kernel_context *ctx, char* serial, size_t len, bool is_hex)
{
	//const auto seed = hash_subserial(serial, len) ^ startup_time;
	const auto serial_hash = hash32(serial);

	if (is_generated_serial(ctx, serial_hash))
	{
		STACK_LOG("randomize_subserial: serial (%s) is already generated, ignore...", serial);
		return;
	}

	auto cached_serial = get_spoofed_cache(ctx, serial_hash);
	if (cached_serial != nullptr)
	{
		for (uint16_t i = 0; i < len; ++i)
			serial[i] = cached_serial[i];

		STACK_LOG("randomize_subserial: using cached serial %s", serial);

		return;
	}

	auto seed = serial_hash ^ ctx->startup_time;

	char spoofed_serial[21] = { 0 };
	for (auto i = 0u; i < len; ++i)
		spoofed_serial[i] = serial[i];

	auto& spoof_hash = ctx->SpoofHash;
	for (auto i = 0u; i < len; ++i)
	{
		if (inline_util::is_good_char(spoofed_serial[i]))
		{
			if (!is_hex)
			{
				spoofed_serial[i] = ((spoofed_serial[i] ^ spoof_hash[i % 16]) % 26) + 65;
				
			}
			else
			{
				auto number_or_letter = (spoofed_serial[i] ^ spoof_hash[i % 16]) % 2;
				if(number_or_letter == 0)
					spoofed_serial[i] = (spoofed_serial[i] ^ spoof_hash[i % 16]) % 6 + 97; // letter a-f
				else
					spoofed_serial[i] = (spoofed_serial[i] ^ spoof_hash[i % 16]) % 10 + 48; // number 0-9
			}
		}
	}
	
	// put into cache
	auto serial_index = ctx->subserial_count++;
	ctx->subserial_cache[serial_index] = serial_hash;
	for (uint16_t i = 0; i < len; ++i)
		ctx->rndsubserial_cache[serial_index][i] = spoofed_serial[i];

	ctx->rndsubserial_hashes[serial_index] = hash32(spoofed_serial);

	// and now finally overwrite
	for (auto i = 0u; i < len; ++i)
		serial[i] = spoofed_serial[i];
}

__forceinline void spoof_serial(kernel_context* ctx, char* serial, bool is_smart)
{
	// must be 20 or less
	size_t len = 20;
	char buf[50];
	bool is_serial_hex = true;

	if (is_smart)
	{
		is_serial_hex = false;
		len = 20;
		//memcpy(buf, serial, 20);
		for (uint16_t i = 0; i < 20; ++i)
			buf[i] = serial[i];
	}
	else
	{
		is_serial_hex = true;
		for (len = 0; serial[len]; ++len)
			if (!inline_util::is_hex(serial[len]))
				is_serial_hex = false;

		//if (is_serial_hex)
		//{
		//	len /= 2;
		//	len = len < 20 ? len : 20;//min(len, 20);
		//	for (auto i = 0u; i < len; ++i)
		//		buf[i] = inline_util::unhex_byte(serial[i * 2], serial[i * 2 + 1]);
		//}
		//else
		//{
			//memcpy(buf, serial, len);
		for (uint16_t i = 0; i < len; ++i)
			buf[i] = serial[i];
		//}
	}

	buf[len] = 0;
	char split[2][20];
	char buf_cpy[50] = { 0 };

	for (uint8_t i = 0; i < sizeof(buf); ++i)
		buf_cpy[i] = buf[i];

	//memset(split, 0, sizeof(split));
	__stosb((unsigned char*)split, 0, sizeof(split));

	for (auto i = 0u; i < len; ++i)
		split[i % 2][i / 2] = buf[i];
	randomize_subserial(ctx, split[0], (len + 1) / 2, is_serial_hex);
	randomize_subserial(ctx, split[1], len / 2, is_serial_hex);

	for (auto i = 0u; i < len; ++i)
		buf[i] = split[i % 2][i / 2];
	buf[len] = 0;

	if (is_smart)
	{
		//memcpy(serial, buf, 20);
		for (uint16_t i = 0; i < 20; ++i)
			serial[i] = buf[i];
	}
	else
	{
		//if (is_serial_hex)
		//{
		//	for (auto i = 0u; i < len; ++i)
		//	{
		//		//std::tie(serial[i * 2], serial[i * 2 + 1]) = hex_byte(buf[i]);
		//		inline_util::hex_byte(buf[i], serial[i * 2], serial[i * 2 + 1]);
		//	}

		//	serial[len * 2] = 0;
		//}
		//else
		//{
			//memcpy(serial, buf, len + 1);

		//if (len >= 14)
		//{
		//	// restore first 9 serial chars
		//	for (uint8_t i = 0; i < 9; ++i)
		//		buf[i] = buf_cpy[i];
		//}

		for (uint16_t i = 0; i < len + 1; ++i)
			serial[i] = buf[i];
		//}
	}
}

__forceinline void spoof_mac(kernel_context* ctx, uint8_t* buf, uint32_t len)
{
	if (len > 8)
	{
		STACK_LOG("spoof_mac: len is too big: %i", len);
		return;
	}

	auto hash = fnva1_buffer(buf, len);
	if (ctx->mac_count > 49)
	{
		ctx->mac_count = 49;
		return;
	}

	for (uint16_t i = 0; i < ctx->mac_count; ++i)
	{
		if (ctx->mac_spoofed_hash_cache[i] == hash)
		{
			STACK_LOG("spoof_mac: mac already spoofed!");
			return;
		}
	}

	for (uint16_t i = 0; i < ctx->mac_count; ++i)
	{
		if (ctx->mac_hash_cache[i] == hash)
		{
			auto spoofed_mac = ctx->mac_spoofed_cache[i];
			inline_util::memcpy(buf, spoofed_mac, len);

			STACK_LOG("spoof_mac: mac spoofed from cache!");

			return;
		}
	}

	uint8_t spoofed_mac[8] = { 0 };
	for (auto i = 0u; i < len; ++i)
	{
		spoofed_mac[i] = buf[i] ^ ctx->SpoofHash[i % 16];
	}

	// put into cache
	auto index = ctx->mac_count++;
	ctx->mac_hash_cache[index] = hash;
	for (auto i = 0u; i < len; ++i)
		ctx->mac_spoofed_cache[index][i] = spoofed_mac[i];
	ctx->mac_spoofed_hash_cache[index] = fnva1_buffer(spoofed_mac, len);

	STACK_LOG("Spoof MAC: %llx -> %llx", *(uint64_t*)buf, *(uint64_t*)spoofed_mac);

	// and now overwrite
	inline_util::memcpy(buf, spoofed_mac, len);
}

namespace Shell17
{
#define SHELL17_SECTION_NAME "shell17"

	__declspec(allocate(SHELL17_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL17_SECTION_NAME))
		uintptr_t SHELL17_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL17_SECTION_NAME)) NTSTATUS NsiEnumerateObjectsAllParametersExHook(uint64_t nsiParams)
	{
		auto ctx = ctx_ptr;
		//auto ret = ctx->NsiEnumerateObjectsAllParametersExOrig((PVOID)nsiParams);
		//STACK_LOG("ret: %llx, +0x00: %llx, +0x08: %llx, +0x10: %llx, +0x18: %llx, +0x20: %llx",
		//	ret, *(uint64_t*)(nsiParams), *(uint64_t*)(nsiParams + 0x8), *(uint64_t*)(nsiParams + 0x10), *(uint64_t*)(nsiParams + 0x18),
		//	*(uint64_t*)(nsiParams + 0x20));
		STACK_LOG("NsiEnumerateObjectsAllParametersExHook: %llx", nsiParams);
		return 0;
	}
}

namespace Shell16
{
#define SHELL16_SECTION_NAME "shell16"

	__declspec(allocate(SHELL16_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL16_SECTION_NAME))
		uintptr_t SHELL16_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL16_SECTION_NAME)) NTSTATUS nsi_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);

			STACK_LOG("nsi_ioc: called");	
			auto params = (NSI_PARAMS*)request.Buffer;
			if (params && NSI_PARAMS_ARP == params->Type) 
			{
				for (auto i = 0u; i < request.BufferLength; ++i)
				{
					volatile auto buf = (uint8_t*)request.BufferLength;
					buf[i] = 0;
				}

				STACK_LOG("handled ARP table\n");
			}
			

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return 0;
	}
}

namespace Shell14
{
#define SHELL14_SECTION_NAME "shell14"

	__declspec(allocate(SHELL14_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL14_SECTION_NAME))
		uintptr_t SHELL14_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL14_SECTION_NAME)) NTSTATUS nic_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);

			STACK_LOG("nic_ioc: called");
			if (irp->MdlAddress)
			{
				// TODO Spoof
				uint64_t system_addr = 0;
				//CALL_RET(system_addr, MmGetSystemAddressForMdlSafe, irp->MdlAddress, /*NormalPagePriority*/16);
				auto Mdl = (_MDL*)irp->MdlAddress;
				if (Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) {
					system_addr = Mdl->MappedSystemVa;
				}
				else {
					CALL_RET(system_addr, MmMapLockedPagesSpecifyCache, Mdl, /*KernelMode*/0, /*MmCached*/1,
						NULL, FALSE, /*Priority*/16);
				}

				if (system_addr)
					spoof_mac(ctx, (uint8_t*)system_addr, 6);
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return 0;
	}
}

namespace Shell13
{
#define SHELL13_SECTION_NAME "shell13"

	__declspec(allocate(SHELL13_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL13_SECTION_NAME))
		uintptr_t SHELL13_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL13_SECTION_NAME)) NTSTATUS scsi_pass_through_direct_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);


			STACK_LOG("scsi_pass_through_direct_ioc: called");
			if (request.BufferLength >= sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER)) {
				auto sb = (SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER*)request.Buffer;
				if (sb->spt.DataIn == SCSI_IOCTL_DATA_IN &&
					sb->spt.CdbLength <= sizeof(sb->spt.Cdb))
				{
					if (sb->spt.DataTransferLength && 
						sb->spt.Cdb[0] == INQUIRY &&
						sb->spt.Cdb[1] == 0x1)
					{
						auto cmd = sb->spt.Cdb[2];
						if (cmd == SCSI_VPD_DEVICE_IDENTIFICATION)
						{
							STACK_LOG("scsi_pass_through_direct_ioc: SCSI_VPD_DEVICE_IDENTIFICATION");
							/*char serialNumber[21] = { 0 };
							auto disk_data = (DWORD*)(info->bBuffer);
							inline_util::convert_to_string(disk_data, 10, 19, serialNumber);

							char old_serial[50] = { 0 };
							inline_util::strcpy(old_serial, serialNumber);

							spoof_serial(request.ctx, serialNumber, false);
							inline_util::convert_to_diskdata(disk_data, 10, 19, serialNumber);

							STACK_LOG("scsi_miniport_ioc: [IOCTL_SCSI_MINIPORT_IDENTIFY] spoofing %s to %s", old_serial, serialNumber);*/
						}
						else if (cmd == SCSI_VPD_UNIT_SERIAL_NUMBER)
						{
							//int len = 1337;
							//auto data_buf = (char*)sb->spt.DataBuffer;
							BOOLEAN result;
							CALL_RET(result, MmIsAddressValid, sb->spt.DataBuffer);
							if (result)
							{
								//STACK_LOG("valid address : %llx, [0] = %x", sb->spt.DataBuffer, *(unsigned char*)(sb->spt.DataBuffer));

								//auto len = data_buf[3];
								//auto serial = data_buf + 4;

								//char old_serial[256] = { 0 };
								//inline_util::strcpy(old_serial, serial);

								//spoof_serial(ctx, serial, false);
								STACK_LOG("SCSI_VPD_UNIT_SERIAL_NUMBER: ScsiStatus: %x, DataTransferLength: %i, DataBuffer: %llx",
									sb->spt.ScsiStatus,
									sb->spt.DataTransferLength, sb->spt.DataBuffer);
							}
							
						}
					}
				}
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return 0;
	}
}

namespace Shell12
{
#define SHELL12_SECTION_NAME "shell12"

	__declspec(allocate(SHELL12_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL12_SECTION_NAME))
		uintptr_t SHELL12_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL12_SECTION_NAME)) NTSTATUS scsi_miniport_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		volatile NTSTATUS fuckyou = 0;
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);

			if (request.BufferLength >= sizeof(SRB_IO_CONTROL)) 
			{
				auto srb = (SRB_IO_CONTROL*)request.Buffer;
				char _sig[10] = { 0 };
				inline_util::strncpy(_sig, (char*)srb->Signature, 8);

				STACK_LOG("srb: {sig: %s, control_code: %x}", _sig, srb->ControlCode);
				PSENDCMDOUTPARAMS  info = (PSENDCMDOUTPARAMS)((char*)request.Buffer + sizeof(SRB_IO_CONTROL));
				if (info->cBufferSize > 0) 
				{
					STACK_LOG("scsi_miniport_ioc: ControlCode: %x", srb->ControlCode);
					if (srb->ControlCode == IOCTL_SCSI_MINIPORT_IDENTIFY)
					{
						//auto device_data = (IDENTIFY_DEVICE_DATA*)(info->bBuffer);

						//char serialNumber[21] = { 0 };
						//inline_util::strncpy(serialNumber, (char*)&device_data->SerialNumber[2], 18);

						//char old_serial[21] = { 0 };
						//inline_util::strncpy(old_serial, serialNumber, 21);

						//spoof_serial(ctx, serialNumber, true);

						//inline_util::strncpy((char*)&device_data->SerialNumber[2], serialNumber, 18);
						
						volatile char serialNumber[21] = { 0 };
						auto disk_data = (unsigned short*)(info->bBuffer);
						inline_util::convert_to_string(disk_data, 10, 19, (char*)serialNumber);

						char old_serial[50] = { 0 };
						inline_util::strncpy(old_serial, (char*)serialNumber, 21);

						spoof_serial(request.ctx, (char*)serialNumber, false);
						inline_util::convert_to_diskdata(disk_data, 10, 19, (char*)serialNumber);

						STACK_LOG("scsi_miniport_ioc: [IOCTL_SCSI_MINIPORT_IDENTIFY] spoofing %s to %s", old_serial, serialNumber);
					}
					else if (srb->ControlCode == NVME_PASS_THROUGH_SRB_IO_CODE)
					{
						STACK_LOG("scsi_miniport_ioc: [NVME_PASS_THROUGH_SRB_IO_CODE] NOT IMPLEMENTED");
					}
				}
				else
				{
					STACK_LOG("cBufferSize: %x, bBuffer: %llx, DriverStatus: {driver_err: %i, ide_err: %i}", info->cBufferSize, info->bBuffer, info->DriverStatus.bDriverError, info->DriverStatus.bIDEError);
				}
				
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return 0;
	}
}

namespace Shell11
{
#define SHELL11_SECTION_NAME "shell11"

	__declspec(allocate(SHELL11_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL11_SECTION_NAME))
		uintptr_t SHELL11_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL11_SECTION_NAME)) NTSTATUS part_layout_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);


			if (request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
				PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
				if (PARTITION_STYLE_GPT == info->PartitionStyle) {
					STACK_LOG("part_layout_ioc: gpt.diskid: %llx %llx", *(uint64_t*)(&info->Gpt.DiskId), *(uint64_t*)((uint64_t*)&info->Gpt.DiskId + 1));
					__stosb((unsigned char*)&info->Gpt.DiskId, 0, sizeof(GUID));
				}
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return /*STATUS_SUCCESS*/0;
	}
}

namespace Shell10
{
#define SHELL10_SECTION_NAME "shell10"

	__declspec(allocate(SHELL10_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL10_SECTION_NAME))
		uintptr_t SHELL10_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL10_SECTION_NAME)) NTSTATUS part_info_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);

			if (request.BufferLength >= sizeof(PARTITION_INFORMATION_EX)) {
				PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
				if (PARTITION_STYLE_GPT == info->PartitionStyle) {
					STACK_LOG("part_info_ioc: gpt.PartitionId: %llx %llx", *(uint64_t*)(&info->Gpt.PartitionId), *(uint64_t*)((uint64_t*)&info->Gpt.PartitionId + 1));
					__stosb((unsigned char*)&info->Gpt.PartitionId, 0, sizeof(GUID));
				}
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return /*STATUS_SUCCESS*/0;
	}
}

namespace Shell5
{
#define SHELL5_SECTION_NAME "shell5"

	__declspec(allocate(SHELL5_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL5_SECTION_NAME))
		uintptr_t SHELL5_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL5_SECTION_NAME)) NTSTATUS smart_data_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);

			if (request.BufferLength >= sizeof(SENDCMDOUTPARAMS)) {
				auto serial = ((PIDSECTOR)((PSENDCMDOUTPARAMS)request.Buffer)->bBuffer)->sSerialNumber;

				char old_serial[50] = { 0 };
				inline_util::strcpy(old_serial, serial);

				spoof_serial(ctx, serial, true);

				STACK_LOG("smart_data_ioc: spoofed %s to %s", old_serial, serial);
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return /*STATUS_SUCCESS*/0;
	}
}

namespace Shell4
{
#define SHELL4_SECTION_NAME "shell4"

	__declspec(allocate(SHELL4_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL4_SECTION_NAME))
		uintptr_t SHELL4_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL4_SECTION_NAME)) NTSTATUS ata_pass_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);

			if (request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA)) {
				PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
				ULONG offset = (ULONG)pte->DataBufferOffset;
				if (offset && offset < request.BufferLength) 
				{
					//auto serial = (char*)&((PIDENTIFY_DEVICE_DATA)((BYTE*)request.Buffer + offset))->SerialNumber[2];
					//char old_serial[50] = { 0 };
					//char serial_flipped[50] = { 0 };
					//inline_util::strcpy(old_serial, serial);

					//inline_util::swap_endianess(serial_flipped, old_serial);
					//spoof_serial(ctx, serial_flipped, true);
					//inline_util::swap_endianess(serial, serial_flipped);

					char serialNumber[21] = { 0 };
					auto disk_data = (unsigned short*)(/*info->bBuffer*/(BYTE*)request.Buffer + offset);
					inline_util::convert_to_string(disk_data, 10, 19, serialNumber);

					char old_serial[50] = { 0 };
					inline_util::strncpy(old_serial, serialNumber, 21);

					spoof_serial(request.ctx, serialNumber, false);
					inline_util::convert_to_diskdata(disk_data, 10, 19, serialNumber);

					STACK_LOG("ata_pass_ioc: spoofed %s to %s", old_serial, serialNumber);
				}
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return /*STATUS_SUCCESS*/0;
	}
}

namespace Shell3
{
#define SHELL3_SECTION_NAME "shell3"

	__declspec(allocate(SHELL3_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL3_SECTION_NAME))
		uintptr_t SHELL3_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL3_SECTION_NAME)) NTSTATUS storage_query_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		volatile NTSTATUS result = 0;
		if (context)
		{
			auto request = *(PIOC_REQUEST)context;
			auto ctx = request.ctx;
			CALL_NRET(ExFreePoolWithTag, context, 0);

			if (request.property_id == StorageDeviceProperty)
			{
				if (request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
					PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)request.Buffer;
					ULONG offset = desc->SerialNumberOffset;
					if (offset && offset < request.BufferLength) {

						auto serial = (CHAR*)desc + offset;

						if (inline_util::strlen(serial) >= 4)
						{
							char old_serial[50] = { 0 };
							inline_util::strcpy(old_serial, serial);

							spoof_serial(ctx, serial, false);

							STACK_LOG("storage_query_ioc: [propid: %i] spoofed serial from %s to %s", request.property_id, old_serial, serial);
						}
					}
				}
			}
			else if (request.property_id == StorageAdapterProtocolSpecificProperty)
			{
				if (request.BufferLength >= sizeof(STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER)) {
				
					auto query = (PSTORAGE_PROPERTY_QUERY)request.Buffer;
					auto protocolData = (PSTORAGE_PROTOCOL_SPECIFIC_DATA2)query->AdditionalParameters;

					auto nvme_data = (nvme_id_ctrl*)((char*)protocolData + protocolData->ProtocolDataOffset);
					auto serial = nvme_data->sn;

					char old_serial[50] = { 0 };
					inline_util::strncpy(old_serial, serial, 20);
						
					char serial_tmp[21] = { 0 };
					inline_util::strncpy(serial_tmp, serial, 20);
						
					spoof_serial(ctx, serial_tmp, false);
					inline_util::strncpy(serial, serial_tmp, 20);

					STACK_LOG("storage_query_ioc: [propid: %i] spoofed serial from %s to %s",
						request.property_id,
						old_serial, serial_tmp);
				
				}
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return /*STATUS_SUCCESS*//*0*/result;
	}
}

namespace handler
{
	__forceinline void change_ioc(kernel_context* ctx, PIO_STACK_LOCATION ioc, PIRP irp, uint64_t routine, bool on_success = true, STORAGE_PROPERTY_ID property_id = (STORAGE_PROPERTY_ID)-1)
	{
		BOOLEAN valid;
		CALL_RET(valid, MmIsAddressValid, ioc->Context);

		if (ioc->Control == SL_INVOKE_ON_SUCCESS && ioc->Context && valid && *(kernel_context**)(ioc->Context) == ctx)
		{
			STACK_LOG("WE ALREADY HOOKED THIS COMPLETION HANDLER???");
			return;
		}

		uint64_t cur_process = NULL;
		CALL_RET(cur_process, IoGetCurrentProcess);

		if (cur_process)
		{
			uint64_t cur_base = NULL;
			CALL_RET(cur_base, PsGetProcessSectionBaseAddress, (PVOID)cur_process);
			if (cur_base && *(uint16_t*)(cur_base + 0x500) == 0x1337)
				return;
		}

		PIOC_REQUEST request = nullptr;
		CALL_RET(request, ExAllocatePool, NonPagedPool, sizeof(IOC_REQUEST));
		if (!request)
			return;

		request->ctx = ctx;
		request->Buffer = irp->AssociatedIrp.SystemBuffer;
		request->BufferLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;
		request->OldContext = ioc->Context;
		request->OldRoutine = 0;//(PIO_COMPLETION_ROUTINE)ioc->CompletionRoutine;
		request->property_id = property_id;

		//ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_CANCEL | SL_INVOKE_ON_ERROR;
		//ioc->Context = request;
		//ioc->CompletionRoutine = (PIO_COMPLETION_ROUTINE)routine;
		CALL_NRET(KseSetCompletionHook, ioc->DeviceObject, irp, (PVOID)routine, request);
	}

	__forceinline bool handle_nvme(kernel_context* ctx, PIO_STACK_LOCATION ioc, PIRP irp)
	{
		// Make sure wmic is still crippled
		bool is_wmip_valid = false;
		CALL_RET(is_wmip_valid, MmIsAddressValid, (PVOID)ctx->WmipInUseRegEntryHead);
		if (is_wmip_valid  &&
			*(uint64_t*)(ctx->WmipInUseRegEntryHead) != ctx->WmipInUseRegEntryHead)
		{
			STACK_LOG("Recrippling wmic...");
			*(uint64_t*)(ctx->WmipInUseRegEntryHead) = ctx->WmipInUseRegEntryHead;
		}

		const auto ioctl_code = ioc->Parameters.DeviceIoControl.IoControlCode;

		STACK_LOG("handle: ioctl_code: %x", ioctl_code);

		switch (ioctl_code)
		{
		case IOCTL_STORAGE_QUERY_PROPERTY:
		{
			auto property_id = ((PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer)->PropertyId;
			if (property_id == StorageDeviceProperty ||
				property_id == StorageAdapterProtocolSpecificProperty)
			{
				STACK_LOG("IOCTL_STORAGE_QUERY_PROPERTY(Control: %x, CompletionRoutine: %llx, Context: %llx, Property: %i",
					ioc->Control, ioc->CompletionRoutine, ioc->Context, property_id);

				change_ioc(ctx, ioc, irp, ctx->storage_query_ioc, true, property_id);
			}
		}
		break;

		case IOCTL_ATA_PASS_THROUGH:
		{
			STACK_LOG("IOCTL_ATA_PASS_THROUGH!");
			change_ioc(ctx, ioc, irp, ctx->ata_pass_ioc);
		}
		break;

		case SMART_RCV_DRIVE_DATA:
		{
			STACK_LOG("SMART_RCV_DRIVE_DATA!");
			change_ioc(ctx, ioc, irp, ctx->smart_data_ioc);
		}
		break;

		case IOCTL_SCSI_MINIPORT:
		{
			STACK_LOG("IOCTL_SCSI_MINIPORT(Control: %x, CompletionRoutine: %llx, Context: %llx",
				ioc->Control, ioc->CompletionRoutine, ioc->Context);
			change_ioc(ctx, ioc, irp, ctx->scsi_miniport_ioc);
		}
		break;

		case IOCTL_SCSI_PASS_THROUGH_DIRECT:
		{
			STACK_LOG("IOCTL_SCSI_PASS_THROUGH_DIRECT(Control: %x, CompletionRoutine: %llx, Context: %llx",
				ioc->Control, ioc->CompletionRoutine, ioc->Context);
			//change_ioc(ctx, ioc, irp, ctx->scsi_pass_through_direct_ioc);
		}
		break;
		}

		return true;
	}

	__forceinline bool handle_partmgr(kernel_context* ctx, PIO_STACK_LOCATION ioc, PIRP irp)
	{
		const auto ioctl_code = ioc->Parameters.DeviceIoControl.IoControlCode;

		STACK_LOG("handle: ioctl_code: %x", ioctl_code);

		switch (ioctl_code)
		{
		
		case IOCTL_DISK_GET_PARTITION_INFO_EX:
			STACK_LOG("IOCTL_DISK_GET_PARTITION_INFO_EX!");
			change_ioc(ctx, ioc, irp, ctx->part_info_ioc);
			break;
		
		case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
			STACK_LOG("IOCTL_DISK_GET_DRIVE_LAYOUT_EX!");
			change_ioc(ctx, ioc, irp, ctx->part_layout_ioc);
			break;
		}

		return true;
	}
}

namespace Shell18
{
#define SHELL18_SECTION_NAME "shell18"

	__declspec(allocate(SHELL18_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL18_SECTION_NAME))
		uintptr_t SHELL18_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL18_SECTION_NAME)) NTSTATUS NsiControlHook(PDEVICE_OBJECT device, PIRP irp)
	{
		auto ctx = ctx_ptr;
		auto ioc = irp->Tail.Overlay.CurrentStackLocation;

		//STACK_LOG("NsiControlHook IoControlCode: %x", ioc->Parameters.DeviceIoControl.IoControlCode);

		switch (ioc->Parameters.DeviceIoControl.IoControlCode)
		{
		case 0x12001B: 
		{
			DWORD length = ioc->Parameters.DeviceIoControl.OutputBufferLength;
			NTSTATUS ret = ctx->NsiControlOrig(device, irp);

			// Fisrt check if its readable at all
			PVOID cur_process;
			CALL_RET(cur_process, IoGetCurrentProcess);

			ULONG dummy = 0;

			NTSTATUS status;
			SIZE_T bytes_copied = 0;
			CALL_RET(status, MmCopyVirtualMemory, cur_process, (PVOID)((uint64_t)irp->UserBuffer + 0x18), cur_process, &dummy, sizeof(dummy), 0, &bytes_copied);

			//PNSI_PARAMS params = (PNSI_PARAMS)irp->UserBuffer;
			if (dummy == NSI_PARAMS_ARP)
			{
				// THIS IS DUMB!
				//for (auto i = 0u; i < length; ++i)
				//{
				//	volatile auto buf = (uint8_t*)irp->UserBuffer;
				//	buf[i] = 0;
				//}

				// spoof correctly now
				auto nsi_params = (NSI_PARAMS*)irp->UserBuffer;

				STACK_LOG("nsi_params (%p): full_length: %x Count: %i, NeighborTable: %p, NeighborTableEntrySize: %x", nsi_params, length, nsi_params->Count,
					nsi_params->NeighborTable, nsi_params->NeighborTableEntrySize);

				if (nsi_params->NeighborTable)
				{
					for (int i = 0; i < nsi_params->Count; ++i)
					{
						auto mac = (uint8_t*)(nsi_params->NeighborTable + i * nsi_params->NeighborTableEntrySize);

						bool valid_mac = false;
						CALL_RET(valid_mac, MmIsAddressValid, mac);
						if (valid_mac && *(uint64_t*)mac != 0)
						{
							/*STACK_LOG("[%i] mac: %llx", i, *(uint64_t*)mac);*/
							spoof_mac(ctx, mac, 6);
						}

						//spoof_mac(ctx, mac, 6);
						//for (auto i = 0u; i < 6; ++i)
						//{
						//	mac[i] ^= ((uint8_t*)(&ctx->xor_key))[i % sizeof(ctx->xor_key)];
						//}
					}

					STACK_LOG("handled ARP1 table\n");
				}
			}
			else
			{
				//STACK_LOG("ARP SPOOF: INVALID type %x", dummy);
			}

			return ret;
		}
		case 0x12000F:
		{
			NTSTATUS ret = ctx->NsiControlOrig(device, irp);

			// Fisrt check if its readable at all
			PVOID cur_process;
			CALL_RET(cur_process, IoGetCurrentProcess);

			ULONG dummy = 0;
			NTSTATUS status;
			SIZE_T bytes_copied = 0;
			CALL_RET(status, MmCopyVirtualMemory, cur_process, (PVOID)((uint64_t)irp->UserBuffer + 0x10), cur_process, &dummy, sizeof(dummy), 0, &bytes_copied);

			if (dummy == 24)
			{
				volatile auto buf = ((uint8_t*)irp->UserBuffer) + 0x128;
				spoof_mac(ctx, buf, 6);
				//for (auto i = 0u; i < 6; ++i)
				//{
				//	buf[i] ^= ((uint8_t*)(&ctx->xor_key))[i % sizeof(ctx->xor_key)];
				//}

				STACK_LOG("handled ARP2 table\n");
			}
			else
			{
				//STACK_LOG("ARP2 SPOOF: invalid type %x", dummy);
			}

			return ret;
		}
			
		}
			
		return ctx->NsiControlOrig(device, irp);
	}
}

namespace Shell15
{
#define SHELL15_SECTION_NAME "shell15"

	__declspec(allocate(SHELL15_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL15_SECTION_NAME))
		uintptr_t SHELL15_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL15_SECTION_NAME)) NTSTATUS NicControlHook(uint64_t fuckthis, PIRP irp)
	{
		auto ctx = ctx_ptr;
		NTSTATUS result = 0;

		auto ioc = irp->Tail.Overlay.CurrentStackLocation;
		auto NICs = (NIC_STRUCT*)ctx->NicsPtr;

		STACK_LOG("NicControlHook called");

		for (DWORD i = 0; i < NICs->Length; ++i)
		{
			PNIC_DRIVER driver = &NICs->Drivers[i];

			if (driver->Original && driver->DriverObject == ioc->DeviceObject->DriverObject)
			{
				//PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
				auto ioc = irp->Tail.Overlay.CurrentStackLocation;
				const auto minor_function = ioc->MinorFunction;
				const auto major_function = ioc->MajorFunction;

				STACK_LOG("NicControlHook IoControlCode: %x, MinorFunction: %x, MajorFunction: %x", ioc->Parameters.DeviceIoControl.IoControlCode, minor_function, major_function);

				switch (ioc->Parameters.DeviceIoControl.IoControlCode)
				{
				case IOCTL_NDIS_QUERY_GLOBAL_STATS:
				{
					switch (*(uint32_t*)irp->AssociatedIrp.SystemBuffer)
					{
					case OID_802_3_PERMANENT_ADDRESS:
					case OID_802_3_CURRENT_ADDRESS:
					case OID_802_5_PERMANENT_ADDRESS:
					case OID_802_5_CURRENT_ADDRESS:
					case OID_WAN_PERMANENT_ADDRESS:
					case OID_WAN_CURRENT_ADDRESS:
					case OID_ARCNET_PERMANENT_ADDRESS:
					case OID_ARCNET_CURRENT_ADDRESS:
						handler::change_ioc(ctx, ioc, irp, ctx->nic_ioc);
						break;
					}

					break;
				}
				case 0x12001B:
					handler::change_ioc(ctx, ioc, irp, ctx->nsi_ioc);
					break;
				}

				return driver->Original(ioc->DeviceObject, irp);
			}
		}

		return result;
	}
}

namespace Shell9
{
#define SHELL9_SECTION_NAME "shell9"

	__declspec(allocate(SHELL9_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL9_SECTION_NAME))
		uintptr_t SHELL9_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL9_SECTION_NAME)) NTSTATUS ATADeviceIdShimHookDeviceControlHook2(PDEVICE_OBJECT device, PIRP irp)
	{
		auto ctx = ctx_ptr;
		NTSTATUS result = 0;
		if (ctx->partmgr_hook_called)
		{
			ctx->partmgr_hook_called = false;
			auto ioc = irp->Tail.Overlay.CurrentStackLocation;
			//handler::handle_partmgr(ctx, ioc, irp);
			handler::handle_nvme(ctx, ioc, irp); // vhdmp
			result = ctx->PartmgrIoctlHandler(device, irp);
		}
		return result;
	}
}

namespace Shell8
{
#define SHELL8_SECTION_NAME "shell8"

	__declspec(allocate(SHELL8_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL8_SECTION_NAME))
		uintptr_t SHELL8_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL8_SECTION_NAME)) uint64_t ATADeviceIdShimHookDeviceControlHook1(PDRIVER_OBJECT driver_object, PIRP irp)
	{
		auto ctx = ctx_ptr;
		ctx->partmgr_hook_called = true;
		return (uint64_t)ctx->error_func_field3;
	}
}


namespace Shell7
{
#define SHELL7_SECTION_NAME "shell7"

	__declspec(allocate(SHELL7_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL7_SECTION_NAME))
		uintptr_t SHELL7_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL7_SECTION_NAME)) NTSTATUS DeviceIdShimHookDeviceControlHook2(PDEVICE_OBJECT device, PIRP irp, uint64_t a3, uint64_t a4)
	{
		auto ctx = ctx_ptr;

		// Otherwise we maybe want to spoof?
		auto ioc = irp->Tail.Overlay.CurrentStackLocation;
		handler::handle_nvme(ctx, ioc, irp);
		return ctx->StorahciIoctlHandler(device, irp);
	}
}

namespace Shell6
{
#define SHELL6_SECTION_NAME "shell6"

	__declspec(allocate(SHELL6_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL6_SECTION_NAME))
		uintptr_t SHELL6_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	// v7 = (*(__int64 (__fastcall **)(_DRIVER_OBJECT *, PIRP))qword_1C0068290)(a1_1->DriverObject, a2);
	__declspec(allocate(SHELL6_SECTION_NAME)) uint64_t DeviceIdShimHookDeviceControlHook1(PDRIVER_OBJECT driver_object, PIRP irp)
	{
		auto ctx = ctx_ptr;
		return (uint64_t)ctx->error_func_field2;
	}
}

namespace Shell2
{
#define SHELL2_SECTION_NAME "shell2"

	__declspec(allocate(SHELL2_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL2_SECTION_NAME))
		uintptr_t SHELL2_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	__declspec(allocate(SHELL2_SECTION_NAME)) NTSTATUS SrbShimHookDeviceControlHook2(PDEVICE_OBJECT device, PIRP irp, uint64_t a3, uint64_t a4)
	{
		auto ctx = ctx_ptr;
		auto ioc = irp->Tail.Overlay.CurrentStackLocation;
		handler::handle_nvme(ctx, ioc, irp);
		return ctx->StornvmeIoctlHandler(device, irp);
	}
}

namespace Shell1
{
#define SHELL1_SECTION_NAME "shell1"

	__declspec(allocate(SHELL1_SECTION_NAME))
		auto ctx_ptr = (kernel_context*)CONTEXT_DEFAULT_MAGIC_VALUE;

	__declspec(allocate(SHELL1_SECTION_NAME))
		uintptr_t SHELL1_END_MARKER = SHELLCODE_END_MARKER_MAGIC;

	// v7 = (*(__int64 (__fastcall **)(_DRIVER_OBJECT *, PIRP))qword_1C0068290)(a1_1->DriverObject, a2);
	__declspec(allocate(SHELL1_SECTION_NAME)) uint64_t SrbShimHookDeviceControlHook1(PDRIVER_OBJECT driver_object, PIRP irp)
	{
		auto ctx = ctx_ptr;
		return (uint64_t)ctx->error_func_field1;
	}
}



int main(int argc, char** argv) {
	//Shell1::SrbShimHookDeviceControlHook1(0, 0);
	//Shell2::SrbShimHookDeviceControlHook2(0, 0);
}