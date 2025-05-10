#include "imports.hpp"
#include "native_imports.hpp"
#include "util.hpp"
#include "sk_crypter.hpp"
#include <ntddk.h>
#include <stdarg.h>

#define DEF_IMPORT(x) decltype(imports::x) imports::x = nullptr


#define IMPORT(lib_name, func_name) { \
	constexpr hash64_t klib_name = kHash64l(#lib_name);\
	constexpr hash64_t kfunc_name = kHash64l(#func_name);\
	constexpr hash32_t k32func_name = kHash32(#func_name);\
	util::module lib_module; \
	util::get_module(skCrypt(#lib_name), lib_module); \
	*(uintptr_t*)&imports::func_name = GetExportHash(lib_module.base, kfunc_name); \
	auto ptr = *(uintptr_t*)&imports::func_name; \
	if (ptr > lib_module.base && ptr < lib_module.base + lib_module.size) \
	{ \
		if (!is_hooked(ptr)) \
		{ \
			*(uint64_t*)&imports::func_name = (uint64_t)CRYPT_IMPORT(func_name); \
		} \
	}\
}

DEF_IMPORT(DbgPrint);
DEF_IMPORT(ExAcquireResourceExclusiveLite);
DEF_IMPORT(ExAllocatePool);
DEF_IMPORT(ExEnterCriticalRegionAndAcquireResourceExclusive);
DEF_IMPORT(ExFreePoolWithTag);
DEF_IMPORT(ExReleaseResourceAndLeaveCriticalRegion);
DEF_IMPORT(ExReleaseResourceLite);
DEF_IMPORT(IoBuildDeviceIoControlRequest);
DEF_IMPORT(IoEnumerateDeviceObjectList);
DEF_IMPORT(IoGetAttachedDeviceReference);
DEF_IMPORT(IoGetCurrentProcess);
DEF_IMPORT(IofCallDriver);
DEF_IMPORT(KeInitializeEvent);
DEF_IMPORT(KeLowerIrql);
DEF_IMPORT(KeStackAttachProcess);
DEF_IMPORT(KeUnstackDetachProcess);
DEF_IMPORT(KeQueryTimeIncrement);
DEF_IMPORT(KeQuerySystemTimePrecise);
DEF_IMPORT(KeWaitForSingleObject);
DEF_IMPORT(KfRaiseIrql);
DEF_IMPORT(KseUnregisterShim);
DEF_IMPORT(MmCopyVirtualMemory);
DEF_IMPORT(MmCopyMemory);
DEF_IMPORT(MmGetSystemAddressForMdlSafe);
DEF_IMPORT(MmGetVirtualForPhysical);
DEF_IMPORT(MmIsAddressValid);
DEF_IMPORT(MmMapIoSpace);
DEF_IMPORT(MmMapIoSpaceEx);
DEF_IMPORT(MmMapLockedPagesSpecifyCache);
DEF_IMPORT(MmUnmapIoSpace);
DEF_IMPORT(ObfDereferenceObject);
DEF_IMPORT(PsAcquireProcessExitSynchronization);
DEF_IMPORT(PsGetCurrentProcessSessionId);
DEF_IMPORT(PsGetProcessDxgProcess);
DEF_IMPORT(PsGetProcessId);
DEF_IMPORT(PsGetProcessSectionBaseAddress);
DEF_IMPORT(PsGetProcessWow64Process);
DEF_IMPORT(PsLookupProcessByProcessId);
DEF_IMPORT(PsReleaseProcessExitSynchronization);
DEF_IMPORT(RtlAnsiStringToUnicodeString);
DEF_IMPORT(RtlCaptureStackBackTrace);
DEF_IMPORT(RtlDeleteElementGenericTableAvl);
DEF_IMPORT(RtlEqualUnicodeString);
DEF_IMPORT(RtlFreeUnicodeString);
DEF_IMPORT(RtlInitAnsiString);
DEF_IMPORT(RtlInitUnicodeString);
DEF_IMPORT(RtlLookupElementGenericTableAvl);
DEF_IMPORT(RtlRandomEx);
DEF_IMPORT(_vsnwprintf);
DEF_IMPORT(RtlUnicodeStringToAnsiString);
DEF_IMPORT(wcsstr);
DEF_IMPORT(ZwQuerySystemInformation);
DEF_IMPORT(ZwOpenKey);
DEF_IMPORT(ZwClose);
DEF_IMPORT(ZwQueryValueKey);
DEF_IMPORT(ZwDeleteValueKey);
DEF_IMPORT(ZwSetValueKey);
DEF_IMPORT(MmGetSystemRoutineAddress);
DEF_IMPORT(ObReferenceObjectByName);
DEF_IMPORT(ObQueryNameString);

namespace imports
{

	bool init(uintptr_t ntos)
	{
		// We need to resolve a few imports before using IMPORT macro
		constexpr hash64_t kZwQuerySystemInformation = kHash64l("ZwQuerySystemInformation");
		constexpr hash64_t kExAllocatePool = kHash64l("ExAllocatePool");
		constexpr hash64_t kExFreePoolWithTag = kHash64l("ExFreePoolWithTag");
		imports::ZwQuerySystemInformation = (imports::ZwQuerySystemInformation_t)GetExportHash(ntos, kZwQuerySystemInformation);
		imports::ZwQuerySystemInformation = CRYPT_IMPORT(ZwQuerySystemInformation);
		imports::ExAllocatePool = (imports::ExAllocatePool_t)GetExportHash(ntos, kExAllocatePool);
		imports::ExAllocatePool = CRYPT_IMPORT(ExAllocatePool);
		imports::ExFreePoolWithTag = (imports::ExFreePoolWithTag_t)GetExportHash(ntos, kExFreePoolWithTag);
		imports::ExFreePoolWithTag = CRYPT_IMPORT(ExFreePoolWithTag);

		// now resolve imports
		IMPORT(ntoskrnl.exe, ExAcquireResourceExclusiveLite);
		//IMPORT(ntoskrnl.exe, ExAllocatePool);
		IMPORT(ntoskrnl.exe, DbgPrint);
		IMPORT(ntoskrnl.exe, ExEnterCriticalRegionAndAcquireResourceExclusive);
		//IMPORT(ntoskrnl.exe, ExFreePoolWithTag);
		IMPORT(ntoskrnl.exe, ExReleaseResourceAndLeaveCriticalRegion);
		IMPORT(ntoskrnl.exe, ExReleaseResourceLite);
		IMPORT(ntoskrnl.exe, IoBuildDeviceIoControlRequest);
		IMPORT(ntoskrnl.exe, IofCallDriver);
		IMPORT(ntoskrnl.exe, IoEnumerateDeviceObjectList);
		IMPORT(ntoskrnl.exe, IoGetAttachedDeviceReference);
		IMPORT(ntoskrnl.exe, IoGetCurrentProcess);
		IMPORT(ntoskrnl.exe, KeInitializeEvent);
		IMPORT(ntoskrnl.exe, KeLowerIrql);
		IMPORT(ntoskrnl.exe, KeStackAttachProcess);
		IMPORT(ntoskrnl.exe, KeUnstackDetachProcess);
		IMPORT(ntoskrnl.exe, KeQuerySystemTimePrecise);
		IMPORT(ntoskrnl.exe, KeQueryTimeIncrement);
		IMPORT(ntoskrnl.exe, KeWaitForSingleObject);
		IMPORT(ntoskrnl.exe, KfRaiseIrql);
		IMPORT(ntoskrnl.exe, KseUnregisterShim);
		IMPORT(ntoskrnl.exe, MmCopyVirtualMemory);
		IMPORT(ntoskrnl.exe, MmCopyMemory);
		IMPORT(ntoskrnl.exe, MmGetSystemAddressForMdlSafe);
		IMPORT(ntoskrnl.exe, MmGetVirtualForPhysical);
		IMPORT(ntoskrnl.exe, MmIsAddressValid);
		IMPORT(ntoskrnl.exe, MmMapIoSpace);
		IMPORT(ntoskrnl.exe, MmMapIoSpaceEx);
		IMPORT(ntoskrnl.exe, MmMapLockedPagesSpecifyCache);
		IMPORT(ntoskrnl.exe, MmUnmapIoSpace);
		IMPORT(ntoskrnl.exe, ObfDereferenceObject);
		IMPORT(ntoskrnl.exe, PsAcquireProcessExitSynchronization);
		IMPORT(ntoskrnl.exe, PsGetCurrentProcessSessionId);
		IMPORT(ntoskrnl.exe, PsGetProcessDxgProcess);
		IMPORT(ntoskrnl.exe, PsGetProcessId);
		IMPORT(ntoskrnl.exe, PsGetProcessSectionBaseAddress);
		IMPORT(ntoskrnl.exe, PsGetProcessWow64Process);
		IMPORT(ntoskrnl.exe, PsLookupProcessByProcessId);
		IMPORT(ntoskrnl.exe, PsReleaseProcessExitSynchronization);
		IMPORT(ntoskrnl.exe, RtlAnsiStringToUnicodeString);
		IMPORT(ntoskrnl.exe, RtlCaptureStackBackTrace);
		IMPORT(ntoskrnl.exe, RtlDeleteElementGenericTableAvl);
		IMPORT(ntoskrnl.exe, RtlEqualUnicodeString);
		IMPORT(ntoskrnl.exe, RtlFreeUnicodeString);
		IMPORT(ntoskrnl.exe, RtlInitAnsiString);
		IMPORT(ntoskrnl.exe, RtlInitUnicodeString);
		IMPORT(ntoskrnl.exe, RtlLookupElementGenericTableAvl);
		IMPORT(ntoskrnl.exe, RtlRandomEx);
		IMPORT(ntoskrnl.exe, _vsnwprintf);
		IMPORT(ntoskrnl.exe, RtlUnicodeStringToAnsiString);
		IMPORT(ntoskrnl.exe, wcsstr);
		IMPORT(ntoskrnl.exe, ZwOpenKey);
		IMPORT(ntoskrnl.exe, ZwClose);
		IMPORT(ntoskrnl.exe, ZwQueryValueKey);
		IMPORT(ntoskrnl.exe, ZwDeleteValueKey);
		IMPORT(ntoskrnl.exe, ZwSetValueKey);
		IMPORT(ntoskrnl.exe, MmGetSystemRoutineAddress);
		IMPORT(ntoskrnl.exe, ObReferenceObjectByName);
		IMPORT(ntoskrnl.exe, ObQueryNameString);

		// init pdb

		return true;
	}
}


NTSTATUS _RtlStringCchPrintfW(wchar_t* pszDest, unsigned __int64 cchDest, const wchar_t* pszFormat, ...)
{
	wchar_t* v3; // r14
	unsigned int v4; // edi
	unsigned __int64 v5; // rsi
	int v6; // eax
	va_list Args; // [rsp+68h] [rbp+20h]

	va_start(Args, pszFormat);
	v3 = pszDest;
	if (cchDest - 1 <= 0x7FFFFFFE)
	{
		v5 = cchDest - 1;
		v4 = 0;
		CALL_RET(v6, _vsnwprintf, pszDest, cchDest - 1, pszFormat, Args);
		if (v6 < 0 || v6 > v5)
		{
			v4 = -2147483643;
		}
		else if (v6 != v5)
		{
			return v4;
		}
		v3[v5] = 0;
		return v4;
	}
	v4 = -1073741811;
	if (cchDest)
		*pszDest = 0;
	return v4;
}