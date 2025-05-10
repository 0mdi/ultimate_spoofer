#include "native_imports.hpp"
#include "windefs.hpp"
#include "peb_defs.hpp"
#include "util.hpp"

void* riCopyMem(void* dest, const void* src, size_t count)
{
	char* dest8 = (char*)dest;
	const char* src8 = (const char*)src;
	while (count--)
	{
		*dest8++ = *src8++;
	}
	return dest;
}
char* riAnsiConvert(const wchar_t* wstr)
{
	int i = 0;

	static char tmpBuf[1000];

	while (wstr[i] != '\0')
	{
		tmpBuf[i] = (char)wstr[i];
		++i;
	}
	tmpBuf[i] = 0;

	return tmpBuf;
}
int riStrLength(const char* s)
{
	int len = 0;
	while (*(s++))
		len++;

	return len;
}
int riToLower(int ch)
{
	if (ch >= 'A' && ch <= 'Z')
		return ch | 32;
	return ch;
}
int riStricmp(const char* s1, const char* s2)
{
	while (riToLower((unsigned char)*s1) == riToLower((unsigned char)*s2)) {
		if (*s1 == '\0')
			return 0;
		s1++; s2++;
	}

	return (int)riToLower((unsigned char)*s1) -
		(int)riToLower((unsigned char)*s2);
}
void riStrCopy(char* buffer, const char* other)
{
	const char* from = other;
	char* to = buffer;

	while (*from)
	{
		*to = *from;

		from++;
		to++;
	}

	*to = 0;
}
char* riStrstr(const char* str, const char* substring)
{
	const char* a = str, * b = substring;
	for (;;) {
		if (!*b) return (char*)str;
		if (!*a) return NULL;
		if (*a++ != *b++) { a = ++str; b = substring; }
	}
}

bool is_forwarded_import(uintptr_t lib_base, uintptr_t address)
{
	auto nth = (IMAGE_NT_HEADERS*)(lib_base + ((IMAGE_DOS_HEADER*)lib_base)->e_lfanew);
	auto export_dir = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	return address >= lib_base + export_dir->VirtualAddress &&
		address <= lib_base + export_dir->VirtualAddress + export_dir->Size;
}

uintptr_t get_forwarded_export(const char* name)
{
	const char* s = name;

	int len = riStrLength(name);

	int i = 0;
	while (*s)
	{
		if (*s == '.')
		{
			char mod_name[255];
			riCopyMem(&mod_name[0], name, i);
			riCopyMem(&mod_name[i], ".dll", 5);

			char fun_name[255];
			riCopyMem(&fun_name[0], (s + 1), (len - i));

			util::module lib_module;
			if (!util::get_module(mod_name, lib_module))
				return 0;
			//auto lib_base = FindModule(kHash64l(mod_name));
			//if (!lib_base)
			//	return 0;

			auto function_addr = GetExportHash(lib_module.base, kHash64l(fun_name));

			if (!function_addr)
				return 0;

			return function_addr;
		}
		s++;
		i++;
	}
	return 0;
}
uintptr_t GetExportHash(uintptr_t module, hash64_t hash)
{
	DWORD_PTR moduleBase = module;
	if (moduleBase)
	{
		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(moduleBase);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(moduleBase + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		auto eDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (eDirectory.VirtualAddress == 0 || eDirectory.Size == 0)
			return 0;


		IMAGE_EXPORT_DIRECTORY* exportTable = (IMAGE_EXPORT_DIRECTORY*)(moduleBase + eDirectory.VirtualAddress);

		DWORD* exportFuncs = (DWORD*)(moduleBase + exportTable->AddressOfFunctions);
		DWORD* exportNames = (DWORD*)(moduleBase + exportTable->AddressOfNames);
		WORD* exportOrdinals = (WORD*)(moduleBase + exportTable->AddressOfNameOrdinals);

		if (!exportFuncs || !exportNames || !exportOrdinals)
			return 0;

		for (DWORD i = 0; i < exportTable->NumberOfFunctions; i++)
		{
			if (i >= exportTable->NumberOfNames)
				break;

			const char* funcName = (const char*)(moduleBase + exportNames[i]);

			static char buf[1000] = { 0 };
			riStrCopy(buf, funcName);

			auto len = riStrLength(buf);

			for (int i = 0; i < len; i++)
				buf[i] = riToLower(buf[i]);


			auto currentHash = hash64(buf);
			if (currentHash == hash)
			{
				auto ordIdx = exportOrdinals[i];
				auto result = moduleBase + exportFuncs[ordIdx];

				while (is_forwarded_import(module, result)) {
					result = get_forwarded_export((const char*)result);
				}

				return result;
			}

		}
	}
	return 0;
}

uintptr_t FindModule(hash64_t moduleHash, size_t* moduleSize)
{
#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif


	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry)
	{
		auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (Current && Current->DllBase)
		{
			if (moduleHash == 0)
				return (uintptr_t)Current->DllBase;

			auto modName = riAnsiConvert(Current->BaseDllName.Buffer);
			auto modNameLen = riStrLength(modName);

			for (int i = 0; i < modNameLen; i++)
				modName[i] = riToLower(modName[i]);

			auto currentHash = hash64((const char*)modName);
			if (currentHash == moduleHash)
			{
				if (moduleSize)
					*moduleSize = Current->SizeOfImage;
				return (uintptr_t)Current->DllBase;
			}
		}
		CurrentEntry = CurrentEntry->Flink;
	}
	return 0;
}