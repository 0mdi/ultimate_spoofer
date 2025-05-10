#include "windefs.hpp"
#include <ntdef.h>

#include "util.hpp"
#include "imports.hpp"
#include "native_imports.hpp"
#include "sk_crypter.hpp"

extern "C" NTSTATUS NTSYSAPI ZwQuerySystemInformation(
	/*SYSTEM_INFORMATION_CLASS*/int SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	ULONG * ReturnLength);

bool util::get_module(char* name, module& out)
{

	int Size = 0;
	NTSTATUS Status;
	CALL_RET(Status, ZwQuerySystemInformation, 0x0B, 0, Size, (PULONG)&Size);
	if (!Size)
	{
		out.base = 0;
		out.size = 0;
		return false;
	}

	PRTL_PROCESS_MODULES Modules = nullptr;
	CALL_RET(Modules, ExAllocatePool, NonPagedPool, Size);
	CALL_RET(Status, ZwQuerySystemInformation, 0x0B, Modules, Size, (PULONG)&Size);
	if (!NT_SUCCESS(Status))
	{
		CALL_NO_RET(ExFreePoolWithTag, Modules, 0);
		out.base = 0;
		out.size = 0;
		return false;
	}

	PRTL_PROCESS_MODULE_INFORMATION m = Modules->Modules;
	for (unsigned int i = 0; i < Modules->NumberOfModules; ++i)
	{
		if (riStrstr((const char*)m[i].FullPathName, name))
		{
			out.base = (UINT64)m[i].ImageBase;
			out.size = m[i].ImageSize;
			return true;
		}
	}

	CALL_NO_RET(ExFreePoolWithTag, Modules, 0);
	out.base = 0;
	out.size = 0;
	return false;
}

bool util::_get_module(char* name, module& out)
{

	int Size = 0;
	NTSTATUS Status;
	Status = ZwQuerySystemInformation(0x0B, 0, Size, (PULONG)&Size);
	if (!Size)
	{
		out.base = 0;
		out.size = 0;
		return false;
	}

	PRTL_PROCESS_MODULES Modules = nullptr;
	Modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, Size);
	Status = ZwQuerySystemInformation(0x0B, Modules, Size, (PULONG)&Size);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(Modules, 0);
		out.base = 0;
		out.size = 0;
		return false;
	}

	PRTL_PROCESS_MODULE_INFORMATION m = Modules->Modules;
	for (unsigned int i = 0; i < Modules->NumberOfModules; ++i)
	{
		if (riStrstr((const char*)m[i].FullPathName, name))
		{
			out.base = (UINT64)m[i].ImageBase;
			out.size = m[i].ImageSize;
			return true;
		}
	}

	ExFreePoolWithTag(Modules, 0);
	out.base = 0;
	out.size = 0;
	return false;
}

bool util::find_processes(char* name, UINT64* pids, UINT32* nums)
{
	ULONG retLen;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	CALL_RET(status, ZwQuerySystemInformation, 0x5, NULL, NULL, &retLen);

	if (!NT_SUCCESS(status))
	{
		PVOID buffer = nullptr;
		CALL_RET(buffer, ExAllocatePool, NonPagedPool, retLen);
		if (buffer)
		{
			CALL_RET(status, ZwQuerySystemInformation, 0x05, buffer, retLen, &retLen);
			if (NT_SUCCESS(status))
			{
				ANSI_STRING acProcessName;
				CALL_NO_RET(RtlInitAnsiString, &acProcessName, name);

				UNICODE_STRING uProcessName;
				CALL_NO_RET(RtlAnsiStringToUnicodeString, &uProcessName, &acProcessName, TRUE);


				_SYSTEM_PROCESS_INFORMATION2* processInfo = (_SYSTEM_PROCESS_INFORMATION2*)buffer;
				while (processInfo->NextEntryOffset)
				{
					BOOLEAN result;
					CALL_RET(result, RtlEqualUnicodeString, &uProcessName, &processInfo->ImageName, TRUE);
					if (result)
					{
						pids[*nums] = (UINT64)processInfo->UniqueProcessId;
						++* nums;
						status = STATUS_SUCCESS;
					}
					processInfo = (PSYSTEM_PROCESS_INFORMATION2)((DWORD_PTR)processInfo + processInfo->NextEntryOffset);
				}

				CALL_NO_RET(RtlFreeUnicodeString, &uProcessName);
			}
			//ExFreePool(buffer);
			CALL_NO_RET(ExFreePoolWithTag, buffer, 0);
		}
	}

	return status;
}

PVOID pProc;
char kapc[100];

bool util::attach_win32k()
{
	UINT64 Procs[100];
	UINT32 num = 0;
	util::find_processes(skCrypt("csrss.exe"), &Procs[0], &num);


	util::module win32kbase;
	util::get_module(skCrypt("win32kbase.sys"), win32kbase);

	if (num > 0)
	{
		for (int i = 0; i < num; i++)
		{
			NTSTATUS status;
			CALL_RET(status, PsLookupProcessByProcessId, (HANDLE)Procs[i], (PEPROCESS*)&pProc);
			if (NT_SUCCESS(status))
			{
				CALL_NO_RET(PsAcquireProcessExitSynchronization, pProc);
				CALL_NO_RET(KeStackAttachProcess, (PRKPROCESS)pProc, &kapc);

				int userSession;
				CALL_RET(userSession, PsGetCurrentProcessSessionId);
				if (userSession != 0)
				{
					BOOLEAN result;
					CALL_RET(result, MmIsAddressValid, (void*)win32kbase.base);
					if (result)
						return true;
				}

				CALL_NO_RET(KeUnstackDetachProcess, &kapc);
			}
		}
	}
	return false;
}

bool util::detach_win32k()
{
	CALL_NO_RET(KeUnstackDetachProcess, &kapc);
	CALL_NO_RET(ObfDereferenceObject, pProc);
	CALL_NO_RET(PsReleaseProcessExitSynchronization, pProc);

	return true;
}

UINT64 util::find_export(UINT64 base, const char* export_name)
{
	//return (UINT64)RtlFindExportedRoutineByName((PVOID)base, export_name);
	return 0;
}

UINT64 util::find_section(UINT64 base, const char* section_name, PULONG section_size)
{
	size_t namelength = riStrLength(section_name);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, section_name, namelength) == 0 &&
			namelength == riStrLength((char*)section->Name)) {
			if (section_size) {
				*section_size = section->Misc.VirtualSize;
			}
			return (UINT64)(base + section->VirtualAddress);
		}
	}
	return 0;
}

bool util::memcpy_protected(VOID* Destination, VOID * Source, ULONG Length)
{
	//Change memory properties.
	PMDL g_pmdl = IoAllocateMdl(Destination, Length, 0, 0, NULL);
	if (!g_pmdl)
		return false;
	MmBuildMdlForNonPagedPool(g_pmdl);
	unsigned int* Mapped = (unsigned int*)MmMapLockedPages(g_pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(g_pmdl);
		return false;
	}
	KIRQL kirql = KeRaiseIrqlToDpcLevel();

	RtlCopyMemory(Mapped, Source, Length);

	KeLowerIrql(kirql);
	//Restore memory properties.
	MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
	IoFreeMdl(g_pmdl);
	return true;
}