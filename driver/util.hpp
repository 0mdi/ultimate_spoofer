#pragma once
#include <ntdef.h>

namespace util
{
	struct module
	{
		UINT64 base;
		UINT32 size;
	};

	bool get_module(char* name, module& out);
	bool _get_module(char* name, module& out);
	bool find_processes(char* name, UINT64* pids, UINT32* nums);

	bool attach_win32k();
	bool detach_win32k();

	UINT64 find_export(UINT64 base, const char* export_name);
	UINT64 find_section(UINT64 base, const char* section_name, PULONG section_size);

	bool memcpy_protected(VOID* Destination, VOID* Source, ULONG Length);

	// 
	// Asm Helpers
	extern "C" __int64 get_rdi();
}

#define SLEEP(X) {LARGE_INTEGER t; t.QuadPart = X * -10000000; KeDelayExecutionThread(KernelMode, FALSE, &t); }