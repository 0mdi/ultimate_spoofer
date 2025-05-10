#pragma once

#include <pshpack1.h>
struct sub_serial
{
	char serial[11];
};

struct kernel_context
{
	uint8_t  SpoofHash[16];

	using NsiEnumerateObjectsAllParametersEx_t = NTSTATUS(*)(PVOID);
	NsiEnumerateObjectsAllParametersEx_t NsiEnumerateObjectsAllParametersExOrig;

	// NIC
	uint64_t NicsPtr;
	uint64_t nic_ioc;
	uint64_t nsi_ioc;

	// we need this because it can get reset?
	uint64_t WmipInUseRegEntryHead;

	uint64_t xor_key;
	uint16_t subserial_count;
	/*hash32_t*/uint32_t subserial_cache[50];
	char rndsubserial_cache[50][21];
	uint32_t rndsubserial_hashes[50];

	uint16_t mac_count;
	uint64_t mac_hash_cache[50];
	uint8_t  mac_spoofed_cache[50][8];
	uint64_t mac_spoofed_hash_cache[50];


	ULONG startup_time;

	uint64_t storage_query_ioc,
			 ata_pass_ioc,
			 smart_data_ioc,
			 part_info_ioc,
			 part_layout_ioc,
			 scsi_miniport_ioc,
			scsi_pass_through_direct_ioc;

	uint64_t shim_funcs[6];

	uint64_t error_func_field1[50]; // needs to be filled with 
	uint64_t error_func_field2[50]; // needs to be filled with 
	uint64_t error_func_field3[50]; // needs to be filled with

	bool	partmgr_hook_called;
	bool	storahci_hook_called;
	bool	stornvme_hook_called;

	//char serial[25];

	// we need these for our stackwalking to determine which func issues the call
	uint64_t	DeviceIdShimHookDeviceControl,
				ATADeviceIdShimHookDeviceControl,
				SrbShimHookDeviceControl,
				RaDriverDeviceControlIrp;

	// we also need access to the orig qwords
	uint64_t	SrbShimHookDeviceControlQwordOrig,
				DeviceIdShimHookDeviceControlQwordOrig;

	// we also need this
	uint64_t	SrbShimStorageAdapterPropertyCompletionHook,
				DeviceIdShimStorageDeviceIdCompletionHook;

	bool		SrbShimInProgress,
				DeviceIdShimInProgress,
				ATADeviceIdShimInProgress;

	//

	using IoctlHandler_t = NTSTATUS(*)(PDEVICE_OBJECT device, PIRP irp);
	IoctlHandler_t StorahciIoctlHandler;
	IoctlHandler_t StornvmeIoctlHandler;
	IoctlHandler_t PartmgrIoctlHandler;
	IoctlHandler_t NsiControlOrig;

	using DbgPrint_t = ULONG(*)(PCSTR Format, ...);
	DbgPrint_t DbgPrint;

	using MmIsAddressValid_t = BOOLEAN(*)(PVOID VirtualAddress);
	MmIsAddressValid_t MmIsAddressValid;

	using ExAllocatePool_t = PVOID(*)(POOL_TYPE PoolType, SIZE_T NumberOfBytes);
	ExAllocatePool_t ExAllocatePool;

	using ExFreePoolWithTag_t = void(*)(PVOID a, ULONG tag);
	ExFreePoolWithTag_t ExFreePoolWithTag;

	using RtlRandomEx_t = ULONG(*)(ULONG* Seed);
	RtlRandomEx_t RtlRandomEx;

	using KeQuerySystemTimePrecise_t = void(*)(PLARGE_INTEGER CurrentTime);
	KeQuerySystemTimePrecise_t KeQuerySystemTimePrecise;

	using IoMarkIrpPending_t = void(*)(PIRP irp);
	IoMarkIrpPending_t IoMarkIrpPending;

	using KeSetEvent_t = LONG(*)(PRKEVENT Event, KPRIORITY Increment, BOOLEAN Wait);
	KeSetEvent_t KeSetEvent;

	using IoGetCurrentProcess_t = PVOID(*)();
	IoGetCurrentProcess_t IoGetCurrentProcess;

	using PsGetProcessSectionBaseAddress_t = PVOID(*)(PVOID);
	PsGetProcessSectionBaseAddress_t PsGetProcessSectionBaseAddress;

	using RtlCaptureStackBackTrace_t = USHORT(*)(ULONG, ULONG, PVOID*, ULONG*);
	RtlCaptureStackBackTrace_t RtlCaptureStackBackTrace;

	using KseSetCompletionHook_t = NTSTATUS(*)(PDEVICE_OBJECT, PIRP, PVOID handler, PVOID context);
	KseSetCompletionHook_t KseSetCompletionHook;

	using MmGetSystemAddressForMdlSafe_t = PVOID(*)(PVOID, ULONG);
	MmGetSystemAddressForMdlSafe_t MmGetSystemAddressForMdlSafe;

	using MmMapLockedPagesSpecifyCache_t = PVOID(*)(PVOID, uint8_t, uint32_t, PVOID, ULONG, ULONG);
	MmMapLockedPagesSpecifyCache_t MmMapLockedPagesSpecifyCache;

	using MmCopyVirtualMemory_t = NTSTATUS(*)(PVOID, PVOID, PVOID, PVOID, SIZE_T, int, PSIZE_T);
	MmCopyVirtualMemory_t MmCopyVirtualMemory;
};
#include <poppack.h>