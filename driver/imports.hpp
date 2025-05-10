#pragma once
#include "inttypes.hpp"
#include <ntifs.h>
#include <ntddk.h>

#define DECL_IMPORT(x, fn_t) using x ## _t = fn_t; extern x ## _t x

// Deprecated, use the non STRSAFE_ prefixed types instead (e.g. LPSTR or PSTR) as they are the same as these.
typedef _Null_terminated_ char* NTSTRSAFE_PSTR;
typedef _Null_terminated_ const char* NTSTRSAFE_PCSTR;
typedef _Null_terminated_ wchar_t* NTSTRSAFE_PWSTR;
typedef _Null_terminated_ const wchar_t* NTSTRSAFE_PCWSTR;
typedef _Null_terminated_ const wchar_t UNALIGNED* NTSTRSAFE_PCUWSTR;

namespace imports
{
	bool init(uintptr_t ntos);
	
	DECL_IMPORT(DbgPrint, ULONG(*)(PCSTR Format, ...));
	DECL_IMPORT(ExAcquireResourceExclusiveLite, BOOLEAN(*)(PERESOURCE, BOOLEAN));
	DECL_IMPORT(ExAllocatePool, PVOID(*)(POOL_TYPE, SIZE_T));
	DECL_IMPORT(ExEnterCriticalRegionAndAcquireResourceExclusive, PVOID(*)(PERESOURCE));
	DECL_IMPORT(ExFreePoolWithTag, void(*)(PVOID, ULONG));
	DECL_IMPORT(ExReleaseResourceAndLeaveCriticalRegion, void(*)(PERESOURCE));
	DECL_IMPORT(ExReleaseResourceLite, void(*)(PERESOURCE));
	DECL_IMPORT(IoBuildDeviceIoControlRequest, PIRP(*)(ULONG, PDEVICE_OBJECT, PVOID, ULONG, PVOID, ULONG, BOOLEAN, PKEVENT, PIO_STATUS_BLOCK));
	DECL_IMPORT(IofCallDriver, NTSTATUS(*)(PDEVICE_OBJECT, PIRP));
	DECL_IMPORT(IoEnumerateDeviceObjectList, NTSTATUS(*)(PDRIVER_OBJECT, PDEVICE_OBJECT*, ULONG, PULONG));
	DECL_IMPORT(IoGetAttachedDeviceReference, PDEVICE_OBJECT(*)(PDEVICE_OBJECT DeviceObject));
	DECL_IMPORT(IoGetCurrentProcess, PEPROCESS(*)());
	DECL_IMPORT(KeInitializeEvent, void(*)(PRKEVENT, EVENT_TYPE, BOOLEAN));
	DECL_IMPORT(KeLowerIrql, void(*)(KIRQL));
	DECL_IMPORT(KeStackAttachProcess, void(*)(PEPROCESS, PVOID));
	DECL_IMPORT(KeUnstackDetachProcess, void(*)(PVOID));
	DECL_IMPORT(KeQuerySystemTimePrecise, void(*)(PLARGE_INTEGER CurrentTime));
	DECL_IMPORT(KeQueryTimeIncrement, ULONG(*)());
	DECL_IMPORT(KeWaitForSingleObject, NTSTATUS(*)(PVOID, KWAIT_REASON WaitReason, KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER));
	DECL_IMPORT(KfRaiseIrql, KIRQL(*)(KIRQL));
	DECL_IMPORT(KseUnregisterShim, NTSTATUS(*)(PVOID));
	DECL_IMPORT(MmCopyMemory, NTSTATUS(*)(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T));
	DECL_IMPORT(MmCopyVirtualMemory, NTSTATUS(*)(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T));
	DECL_IMPORT(MmGetSystemAddressForMdlSafe, PVOID(*)(PMDL Mdl, ULONG Priority));
	DECL_IMPORT(MmGetVirtualForPhysical, PVOID(*)(PHYSICAL_ADDRESS));
	DECL_IMPORT(MmIsAddressValid, BOOLEAN(*)(PVOID));
	DECL_IMPORT(MmMapIoSpace, PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE));
	DECL_IMPORT(MmMapIoSpaceEx, PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, ULONG));
	DECL_IMPORT(MmMapLockedPagesSpecifyCache, PVOID(*)(PMDL, KPROCESSOR_MODE, MEMORY_CACHING_TYPE, PVOID, ULONG, ULONG));
	DECL_IMPORT(MmUnmapIoSpace, void(*)(PVOID, SIZE_T));
	DECL_IMPORT(ObfDereferenceObject, LONG_PTR(*)(PVOID));
	DECL_IMPORT(PsAcquireProcessExitSynchronization, NTSTATUS(*)(PVOID));
	DECL_IMPORT(PsGetCurrentProcessSessionId, int(*)());
	DECL_IMPORT(PsGetProcessDxgProcess, PVOID(*)(PVOID));
	DECL_IMPORT(PsGetProcessId, HANDLE(*)(PEPROCESS Process));
	DECL_IMPORT(PsGetProcessSectionBaseAddress, PVOID(*)(PEPROCESS));
	DECL_IMPORT(PsGetProcessWow64Process, PVOID(*)(PEPROCESS));
	DECL_IMPORT(PsLookupProcessByProcessId, NTSTATUS(*)(HANDLE, PEPROCESS*));
	DECL_IMPORT(PsReleaseProcessExitSynchronization, void(*)(PVOID));
	DECL_IMPORT(RtlAnsiStringToUnicodeString, NTSTATUS(*)(PUNICODE_STRING, PCANSI_STRING, BOOLEAN));
	DECL_IMPORT(RtlCaptureStackBackTrace, USHORT(*)(ULONG, ULONG, PVOID*, PULONG));
	DECL_IMPORT(RtlDeleteElementGenericTableAvl, BOOLEAN(*)(PRTL_AVL_TABLE, PVOID));
	DECL_IMPORT(RtlEqualUnicodeString, BOOLEAN(*)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN));
	DECL_IMPORT(RtlFreeUnicodeString, void(*)(PUNICODE_STRING));
	DECL_IMPORT(RtlInitAnsiString, void(*)(PANSI_STRING, PCSZ));
	DECL_IMPORT(RtlInitUnicodeString, void(*)(PUNICODE_STRING, PCWSTR));
	DECL_IMPORT(RtlLookupElementGenericTableAvl, PVOID(*)(PRTL_AVL_TABLE, PVOID));
	DECL_IMPORT(RtlRandomEx, ULONG(*)(PULONG));
	DECL_IMPORT(_vsnwprintf, NTSTATUS(*)(NTSTRSAFE_PWSTR, size_t, NTSTRSAFE_PCWSTR, ...));
	DECL_IMPORT(RtlUnicodeStringToAnsiString, NTSTATUS(*)(PANSI_STRING, PCUNICODE_STRING, BOOLEAN));
	DECL_IMPORT(wcsstr, wchar_t*(*)(const wchar_t*, const wchar_t*));
	DECL_IMPORT(ZwQuerySystemInformation, NTSTATUS(*)(int, PVOID, ULONG, PULONG));
	DECL_IMPORT(ZwOpenKey, NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
	DECL_IMPORT(ZwClose, NTSTATUS(*)(HANDLE));
	DECL_IMPORT(ZwQueryValueKey, NTSTATUS(*)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG));
	DECL_IMPORT(ZwDeleteValueKey, NTSTATUS(*)(HANDLE, PUNICODE_STRING));
	DECL_IMPORT(ZwSetValueKey, NTSTATUS(*)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
	DECL_IMPORT(MmGetSystemRoutineAddress, PVOID(*)(PUNICODE_STRING));
	DECL_IMPORT(ObReferenceObjectByName, NTSTATUS(*)(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*));
	DECL_IMPORT(ObQueryNameString, NTSTATUS(*)(PVOID, POBJECT_NAME_INFORMATION, ULONG, PULONG));
	//DECL_IMPORT(ObfDereferenceObject, NTSTATUS(*)(PVOID));

}

__forceinline bool is_hooked(uintptr_t ptr)
{
	return (*(uint8_t*)ptr == 0xCC || ((*(uint16_t*)ptr == 0xB848 && *(uint16_t*)(ptr + 10) == 0xE0FF) || /*movabs rax, ?; jmp rax;*/
		(*(uint16_t*)ptr == 0xBB48 && *(uint16_t*)(ptr + 10) == 0xE3FF) || /*movabs rbx, ?; jmp rbx;*/
		(*(uint16_t*)ptr == 0xBA49 && *(uint16_t*)(ptr + 10) == 0x41FF) || /*movabs r10, ?; jmp r10;*/
		(*(uint16_t*)ptr == 0xBF48 && *(uint16_t*)(ptr + 10) == 0xE7FF) || /*movabs rdi, ?; jmp rdi;*/
		(*(uint16_t*)ptr == 0xBE48 && *(uint16_t*)(ptr + 10) == 0xE6FF) || /*movabs rsi, ?; jmp rsi;*/
		(*(uint16_t*)ptr == 0xB948 && *(uint16_t*)(ptr + 10) == 0xE1FF) || /*movabs rcx, ?; jmp rcx;*/
		(*(uint16_t*)ptr == 0xBA48 && *(uint16_t*)(ptr + 10) == 0xE2FF)) /*movabs rdx, ?; jmp rdx;*/);
}

NTSTATUS _RtlStringCchPrintfW(wchar_t* pszDest, unsigned __int64 cchDest, const wchar_t* pszFormat, ...);

#define XOR_KEY 0xBBAAA09257FE4FFE
#define CRYPT_ADDR(fn) ((uint64_t)fn ^ XOR_KEY);
#define CRYPT_IMPORT(fn) (decltype(imports::fn))((uint64_t)imports::fn ^ XOR_KEY)
#define CALL_RET(ret, fn, ...) {volatile auto _fn = CRYPT_IMPORT(fn); if(!is_hooked((uintptr_t)_fn)) {ret = (decltype(ret))_fn(__VA_ARGS__);}}
#define CALL_NO_RET(fn, ...) {volatile auto _fn = CRYPT_IMPORT(fn); if(!is_hooked((uintptr_t)_fn)) { _fn(__VA_ARGS__); }}