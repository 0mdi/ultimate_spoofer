
#include "spoofer.hpp"
#include "globals.hpp"
#include "stealthmem.hpp"
#include "disk.hpp"
#include "smbios.hpp"
#include "wmic.hpp"
#include "nic.hpp"
#include "gpu.hpp"

#include "hashmap.hpp"
#include "../driver_shellcode/kernel_context.hpp"

#include "dbglog.hpp"
#include "native_imports.hpp"

kernel_context* g_kernel_context = nullptr;

#define XOR_INIT(imp) {g_kernel_context->imp = (kernel_context::imp ## _t)((uint64_t)CRYPT_IMPORT(imp) ^ g_kernel_context->xor_key);}

bool init_context()
{
	if (!g_kernel_context)
		return false;

	memset(g_kernel_context, 0, sizeof(kernel_context));

	//g_kernel_context->randomized_subserials.init();

	LARGE_INTEGER startup_time = { 0xAABBCCDDEEFF };
	CALL_NO_RET(KeQuerySystemTimePrecise, &startup_time);
	g_kernel_context->startup_time = startup_time.LowPart;
	g_kernel_context->xor_key = startup_time.QuadPart; // such big brain 1234 iq

	memcpy(g_kernel_context->SpoofHash, globals::instance().args.SpoofHash, 16);

	//UNICODE_STRING DbgPrint_str = RTL_CONSTANT_STRING(L"DbgPrint");
	//UNICODE_STRING MmIsAddressValid_str = RTL_CONSTANT_STRING(L"MmIsAddressValid");
	//UNICODE_STRING ExAllocatePool_str = RTL_CONSTANT_STRING(L"ExAllocatePool");
	//UNICODE_STRING ExFreePool_str = RTL_CONSTANT_STRING(L"ExFreePool");
	//UNICODE_STRING RtlRandomEx_str = RTL_CONSTANT_STRING(L"RtlRandomEx");
	//UNICODE_STRING KeQuerySystemTimePrecise_str = RTL_CONSTANT_STRING(L"KeQuerySystemTimePrecise");
	//UNICODE_STRING IoMarkIrpPending_str = RTL_CONSTANT_STRING(L"IoMarkIrpPending");
	//UNICODE_STRING KeSetEvent_str = RTL_CONSTANT_STRING(L"KeSetEvent");

	XOR_INIT(DbgPrint);
	XOR_INIT(MmIsAddressValid);
	XOR_INIT(ExAllocatePool);
	XOR_INIT(ExFreePoolWithTag);
	XOR_INIT(RtlRandomEx);
	XOR_INIT(KeQuerySystemTimePrecise);
	XOR_INIT(IoGetCurrentProcess);
	XOR_INIT(PsGetProcessSectionBaseAddress);
	XOR_INIT(RtlCaptureStackBackTrace);
	XOR_INIT(MmGetSystemAddressForMdlSafe);
	XOR_INIT(MmMapLockedPagesSpecifyCache);
	XOR_INIT(MmCopyVirtualMemory);

	util::module ntos;
	util::get_module(skCrypt("ntoskrnl.exe"), ntos);

	g_kernel_context->KseSetCompletionHook = (kernel_context::KseSetCompletionHook_t)((ntos.base + globals::instance().args.KseSetCompletionHook) ^ g_kernel_context->xor_key);

	//XOR_INIT(IoMarkIrpPending);
	//XOR_INIT(KeSetEvent);

	/*g_kernel_context->DbgPrint = (kernel_context::DbgPrint_t)MmGetSystemRoutineAddress(&DbgPrint_str);
	g_kernel_context->MmIsAddressValid = (kernel_context::MmIsAddressValid_t)MmGetSystemRoutineAddress(&MmIsAddressValid_str);
	g_kernel_context->ExAllocatePool = (kernel_context::ExAllocatePool_t)MmGetSystemRoutineAddress(&ExAllocatePool_str);
	g_kernel_context->ExFreePool = (kernel_context::ExFreePool_t)MmGetSystemRoutineAddress(&ExFreePool_str);
	g_kernel_context->RtlRandomEx = (kernel_context::RtlRandomEx_t)MmGetSystemRoutineAddress(&RtlRandomEx_str);
	g_kernel_context->KeQuerySystemTimePrecise = (kernel_context::KeQuerySystemTimePrecise_t)MmGetSystemRoutineAddress(&KeQuerySystemTimePrecise_str);
	g_kernel_context->IoMarkIrpPending = (kernel_context::IoMarkIrpPending_t)MmGetSystemRoutineAddress(&IoMarkIrpPending_str);
	g_kernel_context->KeSetEvent = (kernel_context::KeSetEvent_t)MmGetSystemRoutineAddress(&KeSetEvent_str);*/

	g_kernel_context->stornvme_hook_called = false;
	g_kernel_context->partmgr_hook_called = false;
	g_kernel_context->storahci_hook_called = false;
	return true;
}

DRIVER_STATUS spoofer::spoof()
{
	// init kernel_context first
	g_kernel_context = (kernel_context*)stealth::alloc_independent(sizeof(kernel_context));
	if (!g_kernel_context)
		return STEALTHMEM_ALLOC_FAILED;

	if (!init_context())
		return INIT_CONTEXT_FAILED;

	// spoof gpu
	//auto gpu_result = gpu::spoof();
	//if (gpu_result == SUCCESS)
	//{
	//	LOG("gpu spoofed");
	//}
	//else
	//{
	//	LOG("failed to spoof gpu: %llx", gpu_result);
	//}


	// cripple wmic
	auto wmic_status = wmic::cripple();
	if (wmic_status == ALREADY_LOADED)
		return ALREADY_LOADED;

	// spoof disk
	auto result = disk::spoof();
	if (result == SUCCESS)
	{
		LOG("disk spoofed");
	}
	else
	{
		LOG("failed to spoof disk: %llx", result);
	}

	// spoof smbios
	auto smbios_ntstatus = smbios::spoof();
	if (NT_SUCCESS(smbios_ntstatus))
	{
		LOG("smbios spoofed!");
	}
	else
	{
		LOG("failed to spoof smbios: %llx", smbios_ntstatus);
	}

	// spoof mac
	auto nic_result = nic::spoof();
	if (nic_result == SUCCESS)
	{
		LOG("nic spoofed");
	}
	else
	{
		LOG("failed to spoof nic: %llx", nic_result)
	}
	
	if (!NT_SUCCESS(smbios_ntstatus))
		return SMBIOS_FAILED_TO_SPOOF;
	if (nic_result != SUCCESS)
		return NIC_FAILED_TO_SPOOF;

	constexpr uint64_t kVal = SMBIOS_FAILED_TO_SPOOF;

	return result;
}

PVOID spoofer::get_ctx()
{
	return (PVOID)g_kernel_context;
}