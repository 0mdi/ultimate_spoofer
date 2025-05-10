#include "spoofer.hpp"
#include "disk.hpp"
#include "util.hpp"
#include "pattern_scanner.hpp"
#include "sk_crypter.hpp"
#include "stealthmem.hpp"

#include <stdint.h>

#include "../driver_shellcode/kernel_context.hpp"
#include "../driver_shellcode/inline_util.hpp"

#include "shellcode/SrbShimHookDeviceControlHook1.hpp"
#include "shellcode/SrbShimHookDeviceControlHook2.hpp"
#include "shellcode/DeviceIdShimHookDeviceControlHook1.hpp"
#include "shellcode/DeviceIdShimHookDeviceControlHook2.hpp"
#include "shellcode/ATADeviceIdShimHookDeviceControlHook1.hpp"
#include "shellcode/ATADeviceIdShimHookDeviceControlHook2.hpp"
#include "shellcode/storage_query_ioc.hpp"
#include "shellcode/ata_pass_ioc.hpp"
#include "shellcode/smart_data_ioc.hpp"
#include "shellcode/part_info_ioc.hpp"
#include "shellcode/part_layout_ioc.hpp"
#include "shellcode/scsi_miniport_ioc.hpp"
#include "shellcode/scsi_pass_through_direct_ioc.hpp"

#include "dbglog.hpp"
#include "globals.hpp"
#include "hash.hpp"
#include "stack_string.hpp"
#include "native_imports.hpp"
#include "wmic.hpp"
#include <ntstrsafe.h>

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ata.h>
#include <scsi.h>
#include <ntddndis.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <classpnp.h>
#include <ntimage.h>

//constexpr auto kVal = SCSI_PASS_THROUGH_DIRECT;

extern "C"
{
	//NTKERNELAPI NTSTATUS ObReferenceObjectByName(IN PUNICODE_STRING ObjectName, IN ULONG Attributes, IN PACCESS_STATE PassedAccessState, IN ACCESS_MASK DesiredAccess, IN POBJECT_TYPE ObjectType, IN KPROCESSOR_MODE AccessMode, IN OUT PVOID ParseContext, OUT PVOID* Object);
	extern POBJECT_TYPE* IoDriverObjectType;

	//NTKERNELAPI NTSTATUS KseUnregisterShim(PVOID shim);
}

typedef NTSTATUS(__fastcall* RU_REGISTER_INTERFACES)(PVOID device_extension);

// sorry mum
#define STACK_DBGPRINT 0
#if (STACK_DBGPRINT==1)
#define STACK_LOG(x, ...) {STACK_STRING(stack_str, x); CALL_NO_RET(DbgPrint, stack_str, __VA_ARGS__);}
#else
#define STACK_LOG(x, ...) 
#endif

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

__forceinline void randomize_subserial(kernel_context* ctx, char* serial, size_t len, bool is_hex)
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

	auto& spoof_hash = globals::instance().args.SpoofHash;

	for (auto i = 0u; i < len; ++i)
	{
		if (inline_util::is_good_char(spoofed_serial[i]))
		{
			//ULONG rnd1 = 0, rnd2 = 0;
			//CALL_RET(rnd1, RtlRandomEx, (ULONG*)&seed);
			//CALL_RET(rnd2, RtlRandomEx, (ULONG*)&seed);

			if (!is_hex)
			{
				spoofed_serial[i] = ((spoofed_serial[i] ^  spoof_hash[i % 16]) % 26) + 65;
			}
			else
			{
				auto number_or_letter = (spoofed_serial[i] ^ spoof_hash[i % 16]) % 2;
				if (number_or_letter == 0)
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
	memcpy(buf_cpy, buf, sizeof(buf));

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

		for (uint16_t i = 0; i < len + 1; ++i)
			serial[i] = buf[i];
		//}
	}
}

//POBJECT_TYPE* IoDriverObjectType = nullptr;

namespace spoofer::disk
{
	uint64_t	SrbShimHookDeviceControl = 0,
		DeviceIdShimHookDeviceControl = 0,
		ATADeviceIdShimHookDeviceControl = 0;
	uint64_t	SrbShimHookDeviceControlQword = 0,
		DeviceIdShimHookDeviceControlQword = 0,
		ATADeviceIdShimHookDeviceControlQword = 0;

	uint64_t	KseEngine = 0;
	uint64_t	SrbShim = 0,
		DeviceIdShim = 0,
		ATADeviceIdShim = 0;

	// Kse 
	uint64_t __fastcall KsepIsShimRegistered(uint64_t KseEngine, uint64_t* ShimDeref0x8, uint64_t unused, uint64_t* outInternalStruct)
	{
		unsigned int v4; // er8
		uint64_t* outInternalStruct_1; // r11
		uint64_t* ShimDeref0x8_1; // rbx
		uint64_t KseEnginePlus0x10; // r10
		uint64_t* KseEngineDeref0x10; // rcx
		uint64_t v9; // r9
		uint64_t* v10; // rdi
		uint64_t v11; // rdx

		v4 = 0;
		outInternalStruct_1 = outInternalStruct;
		ShimDeref0x8_1 = ShimDeref0x8;
		if (!ShimDeref0x8 || !KseEngine)
			return 0i64;
		KseEnginePlus0x10 = KseEngine + 0x10;
		KseEngineDeref0x10 = *(uint64_t**)(KseEngine + 0x10);
		while (KseEngineDeref0x10 != (uint64_t*)KseEnginePlus0x10)
		{
			v9 = (uint64_t)KseEngineDeref0x10;
			KseEngineDeref0x10 = (uint64_t*)*KseEngineDeref0x10;
			if (!(*(uint32_t*)(v9 + 0x1C) & 4))
			{
				v10 = *(uint64_t**)(*(uint64_t*)(v9 + 16) + 8i64);
				v11 = *v10 - *ShimDeref0x8_1;
				if (*v10 == *ShimDeref0x8_1)
					v11 = v10[1] - ShimDeref0x8_1[1];
				if (!v11)
				{
					if (outInternalStruct_1)
						*outInternalStruct_1 = v9;
					return 1;
				}
			}
		}
		return v4;
	}
	DRIVER_STATUS ForceUnregisterShim(uint64_t Shim)
	{
		uint64_t dkom_struct = 0;
		if (!KsepIsShimRegistered(KseEngine, *(uint64_t**)(Shim + 0x8), 0, &dkom_struct) || !dkom_struct)
		{
			LOG("KsepIsShimRegistered failed");
			return KSE_ENGINE_NOT_FOUND;
		}

		LOG("dkom_struct: %llx, +0x18: %x", dkom_struct, *(uint32_t*)(dkom_struct + 0x18));

		// now dkom
		*(uint32_t*)(dkom_struct + 0x18) = 0;

		// Try to unregister shim so we can abuse it
		NTSTATUS status;
		CALL_RET(status, KseUnregisterShim, (PVOID)Shim);
		if (!NT_SUCCESS(status))
		{
			LOG("KseUnregisterShim failed with %x", status);
			return SHIM_UNREGISTER_FAILED;
		}

		return SUCCESS;
	}
	DRIVER_STATUS DismantleKseShim()
	{
		auto& g = globals::instance();

		if (!g.args.SrbShim || !g.args.DeviceIdShim || !g.args.ATADeviceIdShim)
			return STORPORT_SHIM_NOT_FOUND;

		util::module storport;
		if (!util::get_module(skCrypt("storport.sys"), storport) || !storport.base)
			return STORPORT_NOT_FOUND;

		SrbShim = storport.base + g.args.SrbShim;
		DeviceIdShim = storport.base + g.args.DeviceIdShim;
		ATADeviceIdShim = storport.base + g.args.ATADeviceIdShim;
		LOG("SrbShim: %llx", SrbShim);
		LOG("DeviceIdShim: %llx", DeviceIdShim);
		LOG("ATADeviceIdShim: %llx", ATADeviceIdShim);

		// Now we still need to do 1 little dkom and we can finally unregister
		util::module ntoskrnl;
		if (!util::get_module(skCrypt("ntoskrnl.exe"), ntoskrnl) || !ntoskrnl.base)
			return NTOS_NOT_FOUND;

		const auto KseEngine_offset = globals::instance().args.KseEngine;
		if (!KseEngine_offset)
			return KSE_ENGINE_NOT_FOUND;

		KseEngine = ntoskrnl.base + KseEngine_offset;
		LOG("KseEngine: %llx", KseEngine);

		if (ForceUnregisterShim(SrbShim) != SUCCESS ||
			ForceUnregisterShim(DeviceIdShim) != SUCCESS ||
			ForceUnregisterShim(ATADeviceIdShim) != SUCCESS)
		{
			return KSE_UNREGISTER_FAILED;
		}

		LOG("Shims unregistered!");
		return SUCCESS;
	}

	// 
	DRIVER_STATUS SpoofAndUpdateDiskProperties()
	{
		UNICODE_STRING disk_str;
		CALL_NO_RET(RtlInitUnicodeString, &disk_str, skCrypt(L"\\Driver\\disk"));

		PDRIVER_OBJECT disk_object = 0;

		DRIVER_STATUS result = DRIVER_STATUS::RAID_STORAHCI_DEVICES_ERROR;
		NTSTATUS status;
		CALL_RET(status, ObReferenceObjectByName, &disk_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&disk_object);
		if (NT_SUCCESS(status))
		{
			ULONG length = 0;
			CALL_RET(status, IoEnumerateDeviceObjectList, disk_object, 0, 0, &length);

			if (STATUS_BUFFER_TOO_SMALL == status && length) 
			{
				ULONG size = length * sizeof(PDEVICE_OBJECT);
				PDEVICE_OBJECT* devices = nullptr;
				CALL_RET(devices, ExAllocatePool, NonPagedPool, size);
				if (devices) {
					CALL_RET(status, IoEnumerateDeviceObjectList, disk_object, devices, size, &length);
					if (NT_SUCCESS(status) && length) 
					{
						ULONG success = 0, total = 0;

						for (ULONG i = 0; i < length; ++i) 
						{
							PDEVICE_OBJECT device = devices[i];

							// Update disk properties for disk ID
							PDEVICE_OBJECT disk = nullptr;
							CALL_RET(disk, IoGetAttachedDeviceReference, device);
							if (disk) {
								KEVENT event = { 0 };
								CALL_NO_RET(KeInitializeEvent, &event, NotificationEvent, FALSE);

								PIRP irp = nullptr;
								CALL_RET(irp, IoBuildDeviceIoControlRequest, IOCTL_DISK_UPDATE_PROPERTIES, disk, 0, 0, 0, 0, 0, &event, 0);
								if (irp) 
								{
									NTSTATUS call_status;
									CALL_RET(call_status, IofCallDriver, disk, irp);
									if (STATUS_PENDING == call_status) 
									{
										CALL_NO_RET(KeWaitForSingleObject, &event, Executive, KernelMode, FALSE, 0);
									}
								}
								else 
								{
									LOG("! failed to build IoControlRequest !");
								}

								CALL_NO_RET(ObfDereferenceObject, disk);
							}

							PFUNCTIONAL_DEVICE_EXTENSION ext = (PFUNCTIONAL_DEVICE_EXTENSION)device->DeviceExtension;
							if (ext) 
							{
								//strcpy((PCHAR)ext->DeviceDescriptor + ext->DeviceDescriptor->SerialNumberOffset, SERIAL);
								auto serial = (PCHAR)ext->DeviceDescriptor + ext->DeviceDescriptor->SerialNumberOffset;

								char old_serial[50] = { 0 };
								strcpy(old_serial, serial);
								spoof_serial((kernel_context*)get_ctx(), serial, false);

								LOG("%s: spoofing %s to %s", __FUNCTION__, old_serial, serial);

								++total;
							}

							CALL_NO_RET(ObfDereferenceObject, device);
						}

						LOG("%s: spoofing succeeded for %d/%d", __FUNCTION__, success, total);
						result = SUCCESS;
					}
					else 
					{
						LOG("! failed to get disk devices (got %d): %p !", length, status);
					}

					CALL_NO_RET(ExFreePoolWithTag, devices, 0);
				}
				else 
				{
					LOG("! failed to allocated %d disk devices !", length);
				}
			}
			else 
			{
				LOG("! failed to get disk device list size (got %d): %p !", length, status);
				result = DRIVER_STATUS::STORAHCI_DRIVER_OBJECT_NOT_FOUND;
			}
		}

		return result;
	}

	// RaidUnits
	DRIVER_STATUS SpoofRaidUnitsInternal(RU_REGISTER_INTERFACES RaidUnitRegisterInterfaces, BYTE RaidUnitExtension_SerialNumber_offset) {
		UNICODE_STRING storahci_str;
		CALL_NO_RET(RtlInitUnicodeString,&storahci_str, skCrypt(L"\\Driver\\storahci"));
		PDRIVER_OBJECT storahci_object = 0;

		// Enumerate RaidPorts in storahci
		DRIVER_STATUS result = SUCCESS;
		NTSTATUS status;
		CALL_RET(status, ObReferenceObjectByName, &storahci_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&storahci_object);
		if (NT_SUCCESS(status)) {
			ULONG length = 0;
			CALL_RET(status, IoEnumerateDeviceObjectList, storahci_object, 0, 0, &length);
			if (STATUS_BUFFER_TOO_SMALL == status && length) {
				ULONG size = length * sizeof(PDEVICE_OBJECT);
				PDEVICE_OBJECT* devices = nullptr;
				CALL_RET(devices, ExAllocatePool, NonPagedPool, size);
				if (devices) {
					CALL_RET(status, IoEnumerateDeviceObjectList, storahci_object, devices, size, &length);
					if (NT_SUCCESS(status) && length) {
						for (ULONG i = 0; i < length; ++i) {
							PDEVICE_OBJECT raidport_object = devices[i];

							BYTE buffer[MAX_PATH] = { 0 };
							CALL_RET(status, ObQueryNameString, raidport_object, (POBJECT_NAME_INFORMATION)buffer, sizeof(buffer), &size);
							if (NT_SUCCESS(status)) {
								PUNICODE_STRING raidport_str = (PUNICODE_STRING)buffer;

								// Enumerate devices for each RaidPort
								wchar_t* strresult = nullptr;
								CALL_RET(strresult, wcsstr, raidport_str->Buffer, skCrypt(L"\\RaidPort"));
								if (strresult) {
									DWORD total = 0, success = 0;
									for (PDEVICE_OBJECT device = raidport_object->DriverObject->DeviceObject; device; device = device->NextDevice) {
										if (FILE_DEVICE_DISK == device->DeviceType) {
											PSTRING serial = (PSTRING)((PBYTE)device->DeviceExtension + RaidUnitExtension_SerialNumber_offset);
											
											char old_serial[50] = { 0 };
											inline_util::strncpy(old_serial, serial->Buffer, serial->Length);

											char serialBuf[50] = { 0 };
											inline_util::strncpy(serialBuf, serial->Buffer, serial->Length);

											auto ctx = (kernel_context*)get_ctx();
											spoof_serial(ctx, serialBuf, false);
											LOG("[RAID] spoofing %s to %s", old_serial, serialBuf);
											inline_util::strncpy(serial->Buffer, serialBuf, serial->Length);

											if (NT_SUCCESS(status = RaidUnitRegisterInterfaces(device->DeviceExtension))) {
												++success;
											}
											else {
												LOG("! RaidUnitRegisterInterfaces failed: %p !", status);
											}

											++total;
										}
									}

									LOG("%wZ: RaidUnitRegisterInterfaces succeeded for %d/%d", raidport_str, success, total);
									if (success != total)
										result = RAID_UNIT_NOT_FULLY_SPOOFED;
								}
							}

							CALL_NO_RET(ObfDereferenceObject, raidport_object);
						}
					}
					else {
						LOG("! failed to get storahci devices (got %d): %p !", length, status);
						result = RAID_STORAHCI_DEVICES_ERROR;
					}

					CALL_NO_RET(ExFreePoolWithTag, devices, 0);
				}
				else {
					LOG("! failed to allocated %d storahci devices !", length);
					result = RAID_UNIT_ALLOC_FAILED;
				}
			}
			else {
				LOG("! failed to get storahci device list size (got %d): %p !", length, status);
				result = RAID_STORAHCI_LIST_ERROR;
			}

			CALL_NO_RET(ObfDereferenceObject, storahci_object);
		}
		else {
			LOG("! failed to get %wZ: %p !", &storahci_object, status);
			result = STORAHCI_DRIVER_OBJECT_NOT_FOUND;
		}

		return result;
	}

	// Fdo
	DRIVER_STATUS SpoofFdoExtension()
	{
		UNICODE_STRING storahci_str;
		CALL_NO_RET(RtlInitUnicodeString,  &storahci_str, skCrypt(L"\\Driver\\disk"));
		PDRIVER_OBJECT storahci_object = 0;

		// Enumerate RaidPorts in storahci
		DRIVER_STATUS result = SUCCESS;
		NTSTATUS status;
		CALL_RET(status, ObReferenceObjectByName, &storahci_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&storahci_object);
		if (NT_SUCCESS(status)) {
			ULONG length = 0;
			CALL_RET(status, IoEnumerateDeviceObjectList, storahci_object, 0, 0, &length);
			if (STATUS_BUFFER_TOO_SMALL == status && length) {
				ULONG size = length * sizeof(PDEVICE_OBJECT);
				PDEVICE_OBJECT* devices = nullptr;
				CALL_RET(devices, ExAllocatePool, NonPagedPool, size);
				if (devices) {
					CALL_RET(status, IoEnumerateDeviceObjectList, storahci_object, devices, size, &length);
					if (NT_SUCCESS(status) && length) {
						for (ULONG i = 0; i < length; ++i) {
							PDEVICE_OBJECT raidport_object = devices[i];

							if (raidport_object)
							{
								PFUNCTIONAL_DEVICE_EXTENSION fdoExtension = reinterpret_cast<PFUNCTIONAL_DEVICE_EXTENSION>(raidport_object->DeviceExtension);
								if (fdoExtension)
								{
									PCHAR serialNumber = (PCHAR)fdoExtension->DeviceDescriptor + fdoExtension->DeviceDescriptor->SerialNumberOffset;
									LOG("[FDO] spoofing %s", serialNumber);

									auto ctx = (kernel_context*)get_ctx();
									spoof_serial(ctx, serialNumber, false);
								}
							}

							CALL_NO_RET(ObfDereferenceObject, raidport_object);
						}
					}
					else {
						LOG("! failed to get storahci devices (got %d): %p !", length, status);
						result = RAID_STORAHCI_DEVICES_ERROR;
					}

					CALL_NO_RET(ExFreePoolWithTag, devices, 0);
				}
				else {
					LOG("! failed to allocated %d storahci devices !", length);
					result = RAID_UNIT_ALLOC_FAILED;
				}
			}
			else {
				LOG("! failed to get storahci device list size (got %d): %p !", length, status);
				result = RAID_STORAHCI_LIST_ERROR;
			}

			CALL_NO_RET(ObfDereferenceObject, storahci_object);
		}
		else {
			LOG("! failed to get %wZ: %p !", &storahci_object, status);
			result = STORAHCI_DRIVER_OBJECT_NOT_FOUND;
		}

		return result;
	}

	DRIVER_STATUS SpoofRaidUnits()
	{
		util::module storport = { 0 };
		if (!util::get_module(skCrypt("storport.sys"), storport) || !storport.base || !storport.size)
			return STORPORT_NOT_FOUND;

		PATTERN_SET(storport.base, storport.size);
		auto RaidUnitRegisterInterfaces = (RU_REGISTER_INTERFACES)PATTERN_FIND_CODE("\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x85\xC0");
		if (!RaidUnitRegisterInterfaces)
			return STORPORT_PATTERN_NOT_FOUND;

		auto RaidUnitExtension_SerialNumber = PATTERN_FIND_CODE("\x66\x39\x2C\x41", skCrypt("xxxx"));
		if (!RaidUnitExtension_SerialNumber)
			return STORPORT_PATTERN_NOT_FOUND;

		PATTERN_SET(RaidUnitExtension_SerialNumber, 32);
		RaidUnitExtension_SerialNumber = PATTERN_FIND_CODE("\x4C\x8D\x4F");
		if (!RaidUnitExtension_SerialNumber)
			return STORPORT_PATTERN_NOT_FOUND;

		BYTE RaidUnitExtension_SerialNumber_offset = *(BYTE*)(RaidUnitExtension_SerialNumber + 3);
		RaidUnitRegisterInterfaces = (RU_REGISTER_INTERFACES)((PBYTE)RaidUnitRegisterInterfaces + 8 + *(PINT)((PBYTE)RaidUnitRegisterInterfaces + 4));

		return SpoofRaidUnitsInternal(RaidUnitRegisterInterfaces, RaidUnitExtension_SerialNumber_offset);
	}

	// Spoof registry
	NTSTATUS SpoofRegistryStrValue(WCHAR* RegistryPath, WCHAR* KeyName)
	{
		HANDLE KeyHandle = NULL;
		OBJECT_ATTRIBUTES ObjAttr;

		UNICODE_STRING uRegistryPath;
		CALL_NO_RET(RtlInitUnicodeString, &uRegistryPath, RegistryPath);

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
			CALL_NO_RET(RtlInitUnicodeString, &uKeyName, KeyName);

			unsigned char info_buffer[256] = { 0 };
			auto FullInfo = (KEY_VALUE_FULL_INFORMATION*)info_buffer;
			ULONG FullInfoLen = 0;
			CALL_RET(Status, ZwQueryValueKey, KeyHandle, &uKeyName, KeyValueFullInformation, FullInfo, sizeof(info_buffer), &FullInfoLen);
			if (NT_SUCCESS(Status))
			{
				ANSI_STRING serial_number;
				UNICODE_STRING userial_number;
				userial_number.Buffer = (wchar_t*)(info_buffer + FullInfo->DataOffset);
				userial_number.Length = FullInfo->DataLength;
				userial_number.MaximumLength = FullInfo->DataLength;

				CALL_NO_RET(RtlUnicodeStringToAnsiString, &serial_number, &userial_number, TRUE);

				LOG("[registry] spoofing %s", serial_number.Buffer);
				spoof_serial((kernel_context*)get_ctx(), serial_number.Buffer, false);

				UNICODE_STRING spoofed_key;
				CALL_NO_RET(RtlAnsiStringToUnicodeString, &spoofed_key, &serial_number, TRUE);

				CALL_RET(Status, ZwSetValueKey, KeyHandle,
					&uKeyName,
					0,
					REG_SZ,
					(PVOID)spoofed_key.Buffer,
					(ULONG)(wcslen(spoofed_key.Buffer) * 2) + 1);
			}
			else
			{
				//LOG("failed to query registry key: %x", Status);
			}

			CALL_NO_RET(ZwClose, KeyHandle);
		}
		else
		{
			//LOG("%s: ZwOpenKey failed %X\n", __FUNCTION__, Status);
		}

		return Status;
	}

	NTSTATUS GetRegistryStrValue(WCHAR* RegistryPath, WCHAR* KeyName, PUNICODE_STRING OutStr)
	{
		HANDLE KeyHandle = NULL;
		OBJECT_ATTRIBUTES ObjAttr;

		UNICODE_STRING uRegistryPath;
		CALL_NO_RET(RtlInitUnicodeString, &uRegistryPath, RegistryPath);

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
			CALL_NO_RET(RtlInitUnicodeString, &uKeyName, KeyName);

			unsigned char info_buffer[256] = { 0 };
			auto FullInfo = (KEY_VALUE_FULL_INFORMATION*)info_buffer;
			ULONG FullInfoLen = 0;
			CALL_RET(Status, ZwQueryValueKey, KeyHandle, &uKeyName, KeyValueFullInformation, FullInfo, sizeof(info_buffer), &FullInfoLen);
			if (NT_SUCCESS(Status))
			{
				
				//UNICODE_STRING userial_number;
				//userial_number.Buffer = (wchar_t*)(info_buffer + FullInfo->DataOffset);
				//userial_number.Length = FullInfo->DataLength;
				//userial_number.MaximumLength = FullInfo->DataLength;

				//RtlCopyUnicodeString(OutStr, &userial_number);
				CALL_NO_RET(RtlInitUnicodeString, OutStr, (wchar_t*)(info_buffer + FullInfo->DataOffset));
			}
			else
			{
				//LOG("failed to query registry key: %x", Status);
			}

			CALL_NO_RET(ZwClose, KeyHandle);
		}
		else
		{
			//LOG("%s: ZwOpenKey failed %X\n", __FUNCTION__, Status);
		}

		return Status;
	}

	uint8_t scsi_num = 0;
	wchar_t scsi_drivers[3][25] = { 0 };
	DRIVER_STATUS SaveScsiDriver(int scsi_port)
	{
		if (scsi_num >= 3)
			return DRIVER_STATUS::PARTMGR_DRIVER_OBJECT_NOT_FOUND;

		wchar_t registry_path[110] = { 0 };
		memset(registry_path, 0, sizeof(registry_path));
		_RtlStringCchPrintfW(registry_path, 110, skCrypt(L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d"), scsi_port);
		bool saved = false;

		UNICODE_STRING driver_value;
		if (NT_SUCCESS(GetRegistryStrValue(registry_path, skCrypt(L"Driver"), &driver_value)))
		{
			wcscpy(scsi_drivers[scsi_num++], driver_value.Buffer);
			LOG("Got registry value: %ws, %i", driver_value.Buffer, scsi_port);

			if (!wcscmp(scsi_drivers[scsi_num - 1], driver_value.Buffer))
				saved = true;	
		}

		return saved ? DRIVER_STATUS::SUCCESS : DRIVER_STATUS::STORAHCI_DRIVER_OBJECT_NOT_FOUND;
	}

	DRIVER_STATUS SpoofRegistry()
	{
		bool cleaned = false;
		for (uint32_t i = 0; i < /*MAX_IDE_DRIVES*/16; ++i)
		{
			bool port_saved = false;
			for (uint32_t j = 0; j < 8; ++j)
			{
				wchar_t registry_path[110] = { 0 };
				memset(registry_path, 0, sizeof(registry_path));
				_RtlStringCchPrintfW( registry_path, 110, skCrypt(L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d\\Scsi Bus %d\\Target Id 0\\Logical Unit Id 0"), i, j);

				//LOG("reg_path: %ws", registry_path);

				if (NT_SUCCESS(SpoofRegistryStrValue(registry_path, skCrypt(L"SerialNumber"))))
				{
					LOG("Spoofed registry values for i=%i,j=%i", i, j);
					cleaned = true;

					// also mark this driver for hooking
					if (!port_saved)
					{
						auto scsi_status = SaveScsiDriver(i);
						LOG("MARKED DRIVER FOR HOOKING!");
						port_saved = true;
					}
				}
			}
		}

		return cleaned ? DRIVER_STATUS::SUCCESS : DRIVER_STATUS::NTOS_NOT_FOUND;
	}

	// Hook stuff
	uint64_t FindShimQword(uint64_t func)
	{
		uint64_t result = 0;
		for (uint64_t start = func, cur = start, end = start + 0x100; cur < end; ++cur)
		{
			auto op = (unsigned char*)cur;
			if (op[0] == 0x48 && op[1] == 0x8B && op[2] == 0x05)
			{
				auto offset = *(uint32_t*)(op + 3);
				result = (uint64_t)(op + 7 + offset);
				break;
			}
		}
		return result;
	}
	DRIVER_STATUS spoof()
	{
		// Try to spoof registry first & get scsi drivers
		auto registry_status = SpoofRegistry();
		LOG("SpoofRegistry: %x", registry_status);
		for (uint16_t i = 0; i < scsi_num; ++i)
		{
			LOG("scsi_driver[%i]=%ws", i, scsi_drivers[i]);
		}
		if (!scsi_num)
			return DRIVER_STATUS::RAID_STORAHCI_DEVICES_ERROR;

		// find SrbShimHookDeviceControl in storport.sys
		util::module storport = { 0 };
		if (!util::get_module(skCrypt("storport.sys"), storport) || !storport.base || !storport.size)
			return STORPORT_NOT_FOUND;

		LOG("storport.sys: %llx, %x", storport.base, storport.size);


		if (!globals::instance().args.SrbShimHookDeviceControl || 
			!globals::instance().args.DeviceIdShimHookDeviceControl ||
			!globals::instance().args.ATADeviceIdShimHookDeviceControl)
			return STORPORT_PATTERN_NOT_FOUND;

		auto ctx = (kernel_context*)spoofer::get_ctx();
		ctx->WmipInUseRegEntryHead = spoofer::wmic::WmipInUseRegEntryHead;
		ctx->SrbShimHookDeviceControl = SrbShimHookDeviceControl = storport.base + globals::instance().args.SrbShimHookDeviceControl;
		ctx->DeviceIdShimHookDeviceControl = DeviceIdShimHookDeviceControl = storport.base + globals::instance().args.DeviceIdShimHookDeviceControl;
		ctx->ATADeviceIdShimHookDeviceControl = ATADeviceIdShimHookDeviceControl = storport.base + globals::instance().args.ATADeviceIdShimHookDeviceControl;
		//ctx->RaDriverDeviceControlIrp = storport.base + globals::instance().args.RaDriverDeviceControlIrp;
		ctx->SrbShimStorageAdapterPropertyCompletionHook = storport.base + globals::instance().args.SrbShimStorageAdapterPropertyCompletionHook;
		ctx->DeviceIdShimStorageDeviceIdCompletionHook = storport.base + globals::instance().args.DeviceIdShimStorageDeviceIdCompletionHook;

		LOG("SrbShimHookDeviceControl found @ %llx", SrbShimHookDeviceControl);
		LOG("DeviceIdShimHookDeviceControl found @ %llx", DeviceIdShimHookDeviceControl);
		LOG("ATADeviceIdShimHookDeviceControl found @ %llx", ATADeviceIdShimHookDeviceControl);

		// now find the qword_????? we want to overwrite
		SrbShimHookDeviceControlQword = FindShimQword(SrbShimHookDeviceControl);
		DeviceIdShimHookDeviceControlQword = FindShimQword(DeviceIdShimHookDeviceControl);
		ATADeviceIdShimHookDeviceControlQword = FindShimQword(ATADeviceIdShimHookDeviceControl);

		if (!SrbShimHookDeviceControlQword || !DeviceIdShimHookDeviceControlQword || !ATADeviceIdShimHookDeviceControlQword)
			return STORPORT_QWORD_NOT_FOUND;

		LOG("SrbShimHookDeviceControlQword found @ RVA: %llx", (SrbShimHookDeviceControlQword - storport.base));
		LOG("DeviceIdShimHookDeviceControlQword found @ RVA: %llx", (DeviceIdShimHookDeviceControlQword - storport.base));
		LOG("ATADeviceIdShimHookDeviceControlQword found @ RVA: %llx", (ATADeviceIdShimHookDeviceControlQword - storport.base));

		ctx->SrbShimHookDeviceControlQwordOrig = *(uint64_t*)(SrbShimHookDeviceControlQword);
		ctx->DeviceIdShimHookDeviceControlQwordOrig = *(uint64_t*)(DeviceIdShimHookDeviceControlQword);

		ctx->SrbShimInProgress = ctx->ATADeviceIdShimInProgress = ctx->DeviceIdShimInProgress = false;

		//if (!(ctx->SrbShimHookDeviceControlQwordOrig > storport.base && ctx->SrbShimHookDeviceControlQwordOrig < storport.base + storport.size))
		//{
		//	LOG("Already hooked...");
		//	return ALREADY_LOADED;
		//}

		//LOG("Dismantling Kse...");
		//auto kse_status = DismantleKseShim();
		//if (kse_status != SUCCESS)
		//{
		//	LOG("Failed to dismantle Kse: %x", kse_status);
		//	return kse_status;
		//}

		// now extract & place the shellcode hooks
		uint64_t shell1_allocated = 0;
		{
			auto ptr = SHGetDecryptedSrbShimHookDeviceControlHook1();
			auto size = SHGetSizeSrbShimHookDeviceControlHook1();
			shell1_allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!shell1_allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)shell1_allocated, ptr, size);

			SHDestroySrbShimHookDeviceControlHook1();

			auto shell_ctx = (uint64_t*)(shell1_allocated + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}

		uint64_t shell2_allocated = 0;
		{
			auto ptr = SHGetDecryptedSrbShimHookDeviceControlHook2();
			auto size = SHGetSizeSrbShimHookDeviceControlHook2();
			shell2_allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!shell2_allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)shell2_allocated, ptr, size);

			SHDestroySrbShimHookDeviceControlHook2();

			auto shell_ctx = (uint64_t*)(shell2_allocated + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}

		uint64_t shell3_allocated = 0;
		{
			auto ptr = SHGetDecryptedDeviceIdShimHookDeviceControlHook1();
			auto size = SHGetSizeDeviceIdShimHookDeviceControlHook1();
			shell3_allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!shell3_allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)shell3_allocated, ptr, size);

			SHDestroyDeviceIdShimHookDeviceControlHook1();

			auto shell_ctx = (uint64_t*)(shell3_allocated + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}

		uint64_t shell4_allocated = 0;
		{
			auto ptr = SHGetDecryptedDeviceIdShimHookDeviceControlHook2();
			auto size = SHGetSizeDeviceIdShimHookDeviceControlHook2();
			shell4_allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!shell4_allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)shell4_allocated, ptr, size);

			SHDestroyDeviceIdShimHookDeviceControlHook2();

			auto shell_ctx = (uint64_t*)(shell4_allocated + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}

		uint64_t shell5_allocated = 0;
		{
			auto ptr = SHGetDecryptedATADeviceIdShimHookDeviceControlHook1();
			auto size = SHGetSizeATADeviceIdShimHookDeviceControlHook1();
			shell5_allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!shell5_allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)shell5_allocated, ptr, size);

			SHDestroyATADeviceIdShimHookDeviceControlHook1();

			auto shell_ctx = (uint64_t*)(shell5_allocated + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}

		uint64_t shell6_allocated = 0;
		{
			auto ptr = SHGetDecryptedATADeviceIdShimHookDeviceControlHook2();
			auto size = SHGetSizeATADeviceIdShimHookDeviceControlHook2();
			shell6_allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!shell6_allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)shell6_allocated, ptr, size);

			SHDestroyATADeviceIdShimHookDeviceControlHook2();

			auto shell_ctx = (uint64_t*)(shell6_allocated + size - sizeof(uint64_t));
			if (*shell_ctx != 0xDEAD1234DEADBEEF)
				return INVALID_CTX_MAGIC;

			*shell_ctx = (uint64_t)spoofer::get_ctx();
		}

		// now the ioctl shellcode handler
		//auto ctx = (kernel_context*)spoofer::get_ctx();
	
		// storage_query_ioc
		{
			auto ptr = SHGetDecryptedstorage_query_ioc();
			auto size = SHGetSizestorage_query_ioc();
			auto allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)allocated, ptr, size);
			ctx->storage_query_ioc = allocated;
			SHDestroystorage_query_ioc();		
		}

		// storage_query_ioc
		{
			auto ptr = SHGetDecryptedata_pass_ioc();
			auto size = SHGetSizeata_pass_ioc();
			auto allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)allocated, ptr, size);
			ctx->ata_pass_ioc = allocated;
			SHDestroyata_pass_ioc();
		}

		// smart_data_ioc
		{
			auto ptr = SHGetDecryptedsmart_data_ioc();
			auto size = SHGetSizesmart_data_ioc();
			auto allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)allocated, ptr, size);
			ctx->smart_data_ioc = allocated;
			SHDestroysmart_data_ioc();
		}

		// part_info_ioc
		{
			auto ptr = SHGetDecryptedpart_info_ioc();
			auto size = SHGetSizepart_info_ioc();
			auto allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)allocated, ptr, size);
			ctx->part_info_ioc = allocated;
			SHDestroypart_info_ioc();
		}

		// part_layout_ioc
		{
			auto ptr = SHGetDecryptedpart_layout_ioc();
			auto size = SHGetSizepart_layout_ioc();
			auto allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)allocated, ptr, size);
			ctx->part_layout_ioc = allocated;
			SHDestroypart_layout_ioc();
		}

		// scsi_miniport_ioc
		{
			auto ptr = SHGetDecryptedscsi_miniport_ioc();
			auto size = SHGetSizescsi_miniport_ioc();
			auto allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)allocated, ptr, size);
			ctx->scsi_miniport_ioc = allocated;
			SHDestroyscsi_miniport_ioc();
			LOG("scsi_miniport_ioc: %llx", ctx->scsi_miniport_ioc);
		}

		// scsi_pass_through_direct_ioc
		{
			auto ptr = SHGetDecryptedscsi_pass_through_direct_ioc();
			auto size = SHGetSizescsi_pass_through_direct_ioc();
			auto allocated = stealth::alloc_independent(size < PAGE_SIZE ? PAGE_SIZE : size);
			if (!allocated)
				return STEALTHMEM_ALLOC_FAILED;
			memcpy((PVOID)allocated, ptr, size);
			ctx->scsi_pass_through_direct_ioc = allocated;
			SHDestroyscsi_pass_through_direct_ioc();
			LOG("scsi_pass_through_direct_ioc: %llx", ctx->scsi_pass_through_direct_ioc);
		}

		// last init to kernel_context
		for (uint16_t i = 0; i < ARRAYSIZE(ctx->error_func_field1); ++i)
			ctx->error_func_field1[i] = shell2_allocated;

		for (uint16_t i = 0; i < ARRAYSIZE(ctx->error_func_field2); ++i)
			ctx->error_func_field2[i] = shell4_allocated;

		for (uint16_t i = 0; i < ARRAYSIZE(ctx->error_func_field3); ++i)
			ctx->error_func_field3[i] = shell6_allocated;

		int scsi_drivers_hooked = 0;

		//get nvme driver object
		{
			wchar_t tmp_str[50] = { 0 };
			memset(tmp_str, 0, sizeof(tmp_str));
			RtlStringCchPrintfW(tmp_str, 50, L"\\Driver\\%s", scsi_drivers[0]);

			UNICODE_STRING stornvme_str;
			RtlInitUnicodeString(&stornvme_str, tmp_str);

			PDRIVER_OBJECT stornvme_object = nullptr;
			NTSTATUS status;
			CALL_RET(status, ObReferenceObjectByName, &stornvme_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&stornvme_object);
			if (NT_SUCCESS(status))
			{
				++scsi_drivers_hooked;

				//low_level_disk_hooked = true;
				LOG("Got %ws device object %llx", tmp_str, stornvme_object);

				// finally replace stornvme IRP_MJ
				ctx->StornvmeIoctlHandler = stornvme_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];

				// replace qword_ ptrs first
				ctx->shim_funcs[0] = shell1_allocated;
				ctx->shim_funcs[1] = /*shell2_allocated*/ctx->SrbShimStorageAdapterPropertyCompletionHook;/**(uint64_t*)(ctx->SrbShimHookDeviceControlQwordOrig + 8)*/// this needs to be the original func
				*(uint64_t*)(SrbShimHookDeviceControlQword) = (uint64_t)ctx->shim_funcs;
				LOG("Replaced SrbShimHookDeviceControlQword %llx", (uint64_t)ctx->shim_funcs);

				stornvme_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)SrbShimHookDeviceControl;
				LOG("StornvmeIoctlHandler %llx has been replaced", ctx->StornvmeIoctlHandler);
				ObDereferenceObject(stornvme_object);
			}
			else
			{
				LOG("Could nopt open %ws or raid device object: %llx", tmp_str, status);
			}
		}

		constexpr auto val = IOCTL_SCSI_MINIPORT_IDENTIFY;

		// get storahci driver object
		if (scsi_num > 1)
		{
			wchar_t tmp_str[50] = { 0 };
			memset(tmp_str, 0, sizeof(tmp_str));
			_RtlStringCchPrintfW(tmp_str, 50, skCrypt(L"\\Driver\\%s"), scsi_drivers[1]);

			UNICODE_STRING storahci_str;
			CALL_NO_RET(RtlInitUnicodeString, &storahci_str, tmp_str);
			PDRIVER_OBJECT storahci_object = nullptr;
			NTSTATUS status;
			CALL_RET(status, ObReferenceObjectByName, &storahci_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&storahci_object);
			if (NT_SUCCESS(status))
			{
				++scsi_drivers_hooked;
				LOG("Got %ws device object %llx", tmp_str, storahci_object);

				// finally replace stornvme IRP_MJ
				ctx->StorahciIoctlHandler = storahci_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];

				// replace qword_ ptrs first
				ctx->shim_funcs[2] = shell3_allocated;
				ctx->shim_funcs[3] = /*shell4_allocated*/ctx->DeviceIdShimStorageDeviceIdCompletionHook/**(uint64_t*)(ctx->DeviceIdShimHookDeviceControlQwordOrig + 8)*/;
				*(uint64_t*)(DeviceIdShimHookDeviceControlQword) = (uint64_t)(&ctx->shim_funcs[2]);
				LOG("Replaced DeviceIdShimHookDeviceControlQword %llx", (uint64_t)(&ctx->shim_funcs[2]));

				storahci_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DeviceIdShimHookDeviceControl;
				LOG("StorahciIoctlHandler %llx has been replaced", ctx->StorahciIoctlHandler);
				CALL_NO_RET(ObfDereferenceObject, storahci_object);
				
			}
			else
			{
				LOG("Could nopt open %ws device object: %llx", tmp_str, status);
			}
		}

		// get vhdmp driver object
		if (scsi_num > 2)
		{
			wchar_t tmp_str[50] = { 0 };
			memset(tmp_str, 0, sizeof(tmp_str));
			_RtlStringCchPrintfW( tmp_str, 50, skCrypt(L"\\Driver\\%s"), scsi_drivers[2]);

			UNICODE_STRING partmgr_str;
			CALL_NO_RET(RtlInitUnicodeString, &partmgr_str, tmp_str);
			PDRIVER_OBJECT partmgr_object = nullptr;
			NTSTATUS status;
			CALL_RET(status, ObReferenceObjectByName, &partmgr_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&partmgr_object);
			if (NT_SUCCESS(status))
			{
				++scsi_drivers_hooked;

				LOG("Got %ws device object %llx", tmp_str, partmgr_object);
				
				// replace qword_ ptrs first
				ctx->shim_funcs[4] = shell5_allocated;
				ctx->shim_funcs[5] = /*shell6_allocated*/ctx->DeviceIdShimStorageDeviceIdCompletionHook;
				*(uint64_t*)(ATADeviceIdShimHookDeviceControlQword) = (uint64_t)(&ctx->shim_funcs[4]);
				LOG("Replaced ATADeviceIdShimHookDeviceControlQword %llx", (uint64_t)(&ctx->shim_funcs[4]));

				// finally replace stornvme IRP_MJ
				ctx->PartmgrIoctlHandler = partmgr_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
				partmgr_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)ATADeviceIdShimHookDeviceControl;
				LOG("PartmgrIoctlHandler %llx has been replaced", ctx->PartmgrIoctlHandler);
				CALL_NO_RET(ObfDereferenceObject, partmgr_object);
			}
			else
			{
				LOG("Could nopt open %ws device object: %llx", tmp_str, status);
				//return PARTMGR_DRIVER_OBJECT_NOT_FOUND;
			}
		}

		if (!scsi_drivers_hooked || scsi_drivers_hooked != scsi_num)
		{
			LOG("failed to hook all or at least 1 scsi driver: hooked: %i, max_count: %i", scsi_drivers_hooked, scsi_num);
			return STORAHCI_DRIVER_OBJECT_NOT_FOUND;
		}


		// Now send that update ioctl
		auto driver_status = SpoofAndUpdateDiskProperties();
		if (driver_status != SUCCESS)
		{
			LOG("failed to SpoofAndUpdateDiskProperties! (%x)", driver_status);
		}

		auto raidspoof_status = SpoofRaidUnits();
		LOG("SpoofRaidUnits: %x", raidspoof_status);

		auto fdospoof_status = SpoofFdoExtension();
		LOG("SpoofFdoExtension: %x", fdospoof_status);

		return SUCCESS;
	}
}