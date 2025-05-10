#include "mmap.hpp"
//#include "include/umap.hpp"
#include "hash.hpp"

#include <stdio.h>
#include <string>
#include <TlHelp32.h>



namespace mmap
{
	uint8_t ep_shellcode_ptr_hook[] =
	{
		0x0F, 0xBA, 0x2D, 0x48, 0x00, 0x00, 0x00, 0x00, 0x72, 0x3A, 0x50, 0x51, 0x52, 0x41, 0x50, 0x49,
		0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x33,
		0xC9, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x83, 0xEC, 0x28, 0xFF,
		0xD0, 0x48, 0x83, 0xC4, 0x28, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xF0, 0x83, 0x25, 0x0E, 0x00, 0x00,
		0x00, 0x00, 0x90, 0x90, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xE0,
		0x00, 0x00,0x00,0x00
	};
	uint8_t ep_shellcode_thread[] =
	{
		0x0F, 0xBA, 0x2D, 0x48, 0x00, 0x00, 0x00, 0x00, 0x72, 0x3A, 0x50, 0x51, 0x52, 0x41, 0x50, 0x49,
		0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x33,
		0xC9, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x83, 0xEC, 0x28, 0xFF,
		0xD0, 0x48, 0x83, 0xC4, 0x28, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xF0, 0x83, 0x25, 0x0E, 0x00, 0x00,
		0x00, 0x00, 0x90, 0x90, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,0x00,0x00
	};
	template<class T>
	T read(context& ctx, uintptr_t address)
	{
		T Val{};
		SIZE_T read = 0;
		ReadProcessMemory(ctx.target_process, (void*)address, (void*)&Val, sizeof(T), &read);
		return Val;
	}

	template<class T>
	void write(context& ctx, uintptr_t address, const T& Val)
	{
		SIZE_T written = 0;
		WriteProcessMemory(ctx.target_process, (void*)address, (void*)&Val, sizeof(T), &written);
	}

	void read_memory(context& ctx, uintptr_t address, void* buffer, size_t len)
	{
		SIZE_T read = 0;
		ReadProcessMemory(ctx.target_process, (void*)address, buffer, len, &read);
	}

	void write_memory(context& ctx, uintptr_t address, void* buffer, size_t len)
	{
		SIZE_T read = 0;
		WriteProcessMemory(ctx.target_process, (void*)address, buffer, len, &read);
	}

	uintptr_t get_export(context& ctx, const IMAGE_EXPORT_DIRECTORY& exports, uintptr_t base_addr, hash64_t func_hash)
	{
		UINT16 ordIndex = 0;

		for (DWORD i = 0; i < exports.NumberOfFunctions; ++i)
		{
			if (i < exports.NumberOfNames)
			{
				auto name_addr = (uintptr_t)base_addr + read<DWORD>(ctx, base_addr + exports.AddressOfNames + sizeof(DWORD) * i);

				char funcName[1000];
				read_memory(ctx, name_addr, funcName, 1000);

				//TRACE("%s", funcName);

				auto this_func_hash = kHash64l(funcName);
				if (func_hash == this_func_hash)
				{
					ordIndex = (UINT16)(read<UINT16>(ctx, base_addr + exports.AddressOfNameOrdinals + sizeof(UINT16) * i));
					break;
				}
			}
		}


		if (ordIndex != 0xFFFF)
		{
			PVOID funcAddress = (PVOID)(read<DWORD>(ctx, base_addr + exports.AddressOfFunctions + sizeof(DWORD) * ordIndex) + (uintptr_t)(base_addr));
			return (uintptr_t)funcAddress;
		}

		return 0;
	}
	uintptr_t get_export_ordinal(context& ctx, const IMAGE_EXPORT_DIRECTORY& exports, uintptr_t base_addr, uint16_t ordinal)
	{
		UINT16 ordIndex = ordinal - 1;
		
		if (ordIndex != 0xFFFF)
		{
			PVOID funcAddress = (PVOID)(read<DWORD>(ctx, base_addr + exports.AddressOfFunctions + sizeof(DWORD) * ordIndex) + (uintptr_t)(base_addr));
			return (uintptr_t)funcAddress;
		}

		return 0;
	}

	uintptr_t find_module(context& ctx, hash64_t module_hash)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ctx.target_pid);
		if (snapshot != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32 me32{};
			me32.dwSize = sizeof(me32);

			if (Module32First(snapshot, &me32))
			{
				do
				{
					std::wstring wmod(me32.szModule);
					std::string smod(wmod.begin(), wmod.end());

					if (kHash64l(smod.c_str()) == module_hash || module_hash == 0)
					{
						CloseHandle(snapshot);
						return (uintptr_t)me32.hModule;
					}

				} while (Module32Next(snapshot, &me32));
			}

			CloseHandle(snapshot);
		}
		return 0;
	}

	bool prepare(context& ctx, options& options, uint32_t pid, uintptr_t pe_image, size_t pe_image_len)
	{
		ctx.opt = options;
		ctx.image_base = 0;
		ctx.region_size = 0;
		ctx.target_pid = pid;

		ctx.target_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!ctx.target_process)
		{
			printf("failed to open target process %i\n", pid);
			ctx.result = result::invalid_pid;
			return false;
		}

		ctx.result = result::invalid_image;

		printf("pe_image ptr 0x%llX\n", pe_image);
		if (!pe_image)
			return false;

		if (!pe_image_len)
			return false;

		ctx.pe_image_len = pe_image_len;
		ctx.pe_image = pe_image;

		ctx.result = result::invalid_image;

		printf("check image....\n");
		ctx.pe_image_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ctx.pe_image);

		if (ctx.pe_image_dos->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		ctx.pe_image_nt = reinterpret_cast<PIMAGE_NT_HEADERS>(ctx.pe_image + ctx.pe_image_dos->e_lfanew);

		if (ctx.pe_image_nt->Signature != IMAGE_NT_SIGNATURE)
			return false;

		printf("find ntos....\n");
		ctx.result = result::success;
		return true;
	}

	void cleanup(context& ctx)
	{

	}

	PIMAGE_SECTION_HEADER get_section_header_rva(context& ctx, uint32_t rva)
	{
		PIMAGE_SECTION_HEADER current_section = IMAGE_FIRST_SECTION(ctx.pe_image_nt);
		for (int i = 0; i < ctx.pe_image_nt->FileHeader.NumberOfSections; i++)
		{
			if (rva >= current_section->VirtualAddress &&
				rva < current_section->VirtualAddress + current_section->SizeOfRawData)
			{
				return current_section;
			}
			current_section++;
		}

		return nullptr;
	}
	uintptr_t rva_to_fs(context& ctx, uint32_t rva)
	{
		auto section_header = get_section_header_rva(ctx, rva);
		if (!section_header)
			return 0;

		auto file_offset = (rva - section_header->VirtualAddress + section_header->PointerToRawData);

		return (uintptr_t)(ctx.pe_image) + file_offset;
	}

	void* allocate_private_executable(context& ctx, size_t size)
	{
		return VirtualAllocEx(ctx.target_process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	bool allocate_image(context& ctx)
	{
		ctx.region_size = ctx.pe_image_nt->OptionalHeader.SizeOfImage;

		ctx.image_base = (uintptr_t)allocate_private_executable(ctx, ctx.region_size);

		ctx.shellcode_ptr = ctx.image_base;

		printf("image allocated @ 0x%llX\n", ctx.image_base);

		return ctx.image_base != 0;
	}
	bool map_sections(context& ctx)
	{
		PIMAGE_SECTION_HEADER current_section = IMAGE_FIRST_SECTION(ctx.pe_image_nt);
		if (!current_section)
			return false;

		for (int i = 0; i < ctx.pe_image_nt->FileHeader.NumberOfSections; i++)
		{
			printf("mapping section %s\n", current_section->Name);

			if (current_section->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
			{
				if (current_section->SizeOfRawData > 0)
				{
					auto dst_addr = ctx.image_base + current_section->VirtualAddress;
					auto src_addr = ctx.pe_image + current_section->PointerToRawData;


					printf("copy section %s (%p -> %p) (0x%X)\n", current_section->Name, src_addr, dst_addr, current_section->SizeOfRawData);
					write_memory(ctx, dst_addr, (void*)src_addr, current_section->SizeOfRawData);
				}
				else
				{
					printf("skipping section %s, no raw data\n", current_section->Name);
				}
			}
			else
			{
				printf("skipping section %s, no rwe flags\n", current_section->Name);
			}

			current_section++;
		}
		return true;
	}
	bool process_relocs(context& ctx)
	{
		printf("processing relocations\n");

		int counter = 0;
		IMAGE_DATA_DIRECTORY reloc_dir = ctx.pe_image_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size > 0)
		{
			uintptr_t delta = ctx.image_base - ctx.pe_image_nt->OptionalHeader.ImageBase;

			if (delta == 0)
				return true;

			printf("image_delta: 0x%llX\n", delta);

			PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(rva_to_fs(ctx, reloc_dir.VirtualAddress));
			if (!reloc)
			{
				return false;
			}
			int c = 0;
			while (c < reloc_dir.Size)
			{
				size_t p = sizeof(IMAGE_BASE_RELOCATION);
				uint16_t* chains = (uint16_t*)((PUCHAR)reloc + p);
				if (reloc->SizeOfBlock == 0)
				{
					return false;
				}
				while (p < reloc->SizeOfBlock)
				{
					uintptr_t Base = (uintptr_t)(ctx.image_base + reloc->VirtualAddress);
					switch (*chains >> 12)
					{
					case IMAGE_REL_BASED_HIGHLOW:
					{
						UINT32 oldValue = read<UINT32>(ctx, Base + (*chains & 0xFFF));
						auto newValue = oldValue + (UINT32)delta;
						write(ctx, Base + (*chains & 0xFFF), newValue);
						counter++;

						//printf("processed relocation (32) 0x%X => 0x%X", oldValue, newValue);
						break;
					}
					case IMAGE_REL_BASED_DIR64:
					{
						UINT64 oldValue = read<UINT64>(ctx, Base + (*chains & 0xFFF));
						auto newValue = oldValue + (UINT64)delta;
						write(ctx, Base + (*chains & 0xFFF), newValue);
						counter++;
						//printf("processed relocation (64) 0x%llX => 0x%llX", oldValue, newValue);
						break;
					}
					case IMAGE_REL_BASED_ABSOLUTE: {
						break;
					}
					default: {
						printf("unsupported Relocation type 0x%X!\n", (*chains >> 12));
						break;
					}
					}
					chains++;
					p += sizeof(uint16_t);
				}
				c += reloc->SizeOfBlock;
				reloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)reloc + reloc->SizeOfBlock);
			}
		}
		printf("processed %i relocations\n", counter);
		return true;
	}
	bool is_forwarded_import(context& ctx, uintptr_t lib_base, uintptr_t address)
	{
		auto nth = read<IMAGE_NT_HEADERS>(ctx, lib_base + read<IMAGE_DOS_HEADER>(ctx, lib_base).e_lfanew);
		auto export_dir = &nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		return address >= lib_base + export_dir->VirtualAddress &&
			address <= lib_base + export_dir->VirtualAddress + export_dir->Size;
	}
	uintptr_t get_forwarded_export(context& ctx, const char* name)
	{
		const char* s = name;

		int len = strlen(name);

		int i = 0;
		while (*s)
		{
			if (*s == '.')
			{
				char mod_name[255] = { 0 };
				memcpy(&mod_name[0], name, i);
				memcpy(&mod_name[i], ".dll", 5);

				char fun_name[255] = { 0 };
				memcpy(&fun_name[0], (s + 1), (len - i));


				auto lib_base = find_module(ctx, kHash64l(mod_name));
				if (!lib_base)
					return 0;

				IMAGE_DOS_HEADER eLibDosHeader = read<IMAGE_DOS_HEADER>(ctx, lib_base);
				IMAGE_NT_HEADERS eLibNtHeader = read<IMAGE_NT_HEADERS>(ctx, ((uintptr_t)lib_base) + eLibDosHeader.e_lfanew);
				IMAGE_DATA_DIRECTORY eDirectory = eLibNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				if (eDirectory.VirtualAddress == 0 || eDirectory.Size == 0)
					return false;

				IMAGE_EXPORT_DIRECTORY exports = read<IMAGE_EXPORT_DIRECTORY>(ctx, (uintptr_t)lib_base + eDirectory.VirtualAddress);


				auto function_addr = get_export(ctx, exports, lib_base, kHash64l(fun_name));

				if (!function_addr)
					return 0;

				return function_addr;
			}
			s++;
			i++;
		}
		return 0;
	}
	bool resolve_imports(context& ctx)
	{
		printf("resolving imports\n");
		IMAGE_DATA_DIRECTORY importDir = ctx.pe_image_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!importDir.VirtualAddress || !importDir.Size)
			return true;

		auto import_table = (PIMAGE_IMPORT_DESCRIPTOR)(rva_to_fs(ctx, importDir.VirtualAddress));
		while (import_table->Name)
		{
			auto lib_name = (char*)(rva_to_fs(ctx, import_table->Name));

			char import_module[200];
			strcpy_s<200>(import_module, lib_name);

			printf("resolving imports for %s\n", lib_name);

			BOOLEAN isFreed = FALSE;

			if (strcmp(lib_name, "ole32.dll") == 0)
			{
				strcpy_s<200>(import_module, "combase.dll");
				printf("using ole32->combase hotfix\n");
			}


			auto library_base = find_module(ctx, kHash64l(lib_name));
			if (!library_base)
			{
				printf("Loading module %s\n", lib_name);
				// try to load it but write it to memory first
				char buf[MAX_PATH] = { 0 };
				strcpy_s(buf, lib_name);
				write(ctx, ctx.image_base + 0x500, buf);

				CreateRemoteThread(ctx.target_process, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, (PVOID)(ctx.image_base + 0x500), 0, nullptr);
				Sleep(100);

				library_base = find_module(ctx, kHash64l(lib_name));

			}
			printf("module %s @ 0x%llX\n", lib_name, library_base);

			if (!library_base)
				return false;

			IMAGE_DOS_HEADER eLibDosHeader = read<IMAGE_DOS_HEADER>(ctx, library_base);
			IMAGE_NT_HEADERS eLibNtHeader = read<IMAGE_NT_HEADERS>(ctx, ((uintptr_t)library_base) + eLibDosHeader.e_lfanew);
			IMAGE_DATA_DIRECTORY eDirectory = eLibNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			if (eDirectory.VirtualAddress == 0 || eDirectory.Size == 0)
				return false;

			IMAGE_EXPORT_DIRECTORY exports = read<IMAGE_EXPORT_DIRECTORY>(ctx, (uintptr_t)library_base + eDirectory.VirtualAddress);

			PIMAGE_THUNK_DATA64 thunk = nullptr;
			if (import_table->OriginalFirstThunk == 0)
				thunk = (PIMAGE_THUNK_DATA64)(rva_to_fs(ctx, import_table->FirstThunk));
			else
				thunk = (PIMAGE_THUNK_DATA64)(rva_to_fs(ctx, import_table->OriginalFirstThunk));

			//ULONG_PTR* import_thunk = (ULONG_PTR*)(ctx.image_base + (import_table->FirstThunk));


			int import_index = 0;
			while (thunk->u1.Function)
			{
				uintptr_t function_addr = 0;

				if ((thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) == 0)
				{
					auto name_import = (PIMAGE_IMPORT_BY_NAME)(rva_to_fs(ctx, thunk->u1.AddressOfData));
					function_addr = get_export(ctx, exports, library_base, kHash64l(name_import->Name));

					if (is_forwarded_import(ctx, library_base, function_addr))
					{
						auto forward_name = (const char*)(function_addr);
						function_addr = get_forwarded_export(ctx, forward_name);
					}


					if(!function_addr)
						printf("failed to resolve %s.%s\n", lib_name, name_import->Name);
					else
						printf("resolved %s.%s -> 0x%llX\n", lib_name, name_import->Name, function_addr);
				}
				else
				{
					function_addr = get_export_ordinal(ctx, exports, library_base, thunk->u1.Ordinal & 0xFFFF);

					if (!function_addr)
						printf("failed to resolve %s.%i\n", lib_name, thunk->u1.Ordinal & 0xFFFF);
					else
						printf("resolved %s.%i -> 0x%llX\n", lib_name, thunk->u1.Ordinal & 0xFFFF, function_addr);
				}


				if (!function_addr)
					return false;


				auto imp_thunk_addr = ctx.image_base + (import_table->FirstThunk) + sizeof(uintptr_t) * import_index;
				write(ctx, imp_thunk_addr, function_addr);

				thunk++;
				import_index++;
			}
			import_table++;
		}
		return true;
	}
	bool prepare_shellcode_ptr_hook(context& ctx, uintptr_t originalFunction, uintptr_t callbackPtr)
	{
		uintptr_t entryPointRVA = ctx.pe_image_nt->OptionalHeader.AddressOfEntryPoint;
		uintptr_t entryPointVA = ctx.image_base + entryPointRVA;

		printf("entrypoint @ 0x%llx 0x%llx\n", entryPointRVA, entryPointVA);


		*(uintptr_t*)(ep_shellcode_ptr_hook + 0x11) = ctx.shellcode_ptr;
		*(uintptr_t*)(ep_shellcode_ptr_hook + 0x23) = entryPointVA;
		*(uintptr_t*)(ep_shellcode_ptr_hook + 0x46) = originalFunction;


		write_memory(ctx, ctx.shellcode_ptr, ep_shellcode_ptr_hook, ARRAYSIZE(ep_shellcode_ptr_hook));

		printf("shellcode installed at 0x%llX\n", ctx.shellcode_ptr);

		return true;
	}
	bool prepare_shellcode_thread(context& ctx)
	{
		uintptr_t entryPointRVA = ctx.pe_image_nt->OptionalHeader.AddressOfEntryPoint;
		uintptr_t entryPointVA = ctx.image_base + entryPointRVA;

		printf("entrypoint @ 0x%llx 0x%llx\n", entryPointRVA, entryPointVA);


		*(uintptr_t*)(ep_shellcode_thread + 0x11) = ctx.shellcode_ptr;
		*(uintptr_t*)(ep_shellcode_thread + 0x23) = entryPointVA;


		write_memory(ctx, ctx.shellcode_ptr, ep_shellcode_thread, ARRAYSIZE(ep_shellcode_thread));

		printf("shellcode installed at 0x%llX\n", ctx.shellcode_ptr);

		return true;
	}
	bool hook_executor(context& ctx, uintptr_t value)
	{
		write_memory(ctx, ctx.executor_ptr, &value, sizeof(value));
		return true;
	}
	
	bool call_entrypoint_thread(context& ctx)
	{
		ctx.result = result::loaded_without_execute;

		if (!prepare_shellcode_thread(ctx))
			return false;

		mmap_user_data user_data;
		user_data.magic_value = 0xDEAD1337;
		user_data.shellcode_size = ARRAYSIZE(ep_shellcode_thread);
		user_data.full_size = user_data.shellcode_size + sizeof(mmap_user_data);
		user_data.is_executed = FALSE;
		user_data.module_base = ctx.image_base;
		user_data.image_size = ctx.region_size;
		user_data.expire_seconds = 0;

		memset(user_data.hdd_serial, 0, sizeof(user_data.hdd_serial));

		write_memory(ctx, (ctx.shellcode_ptr + ARRAYSIZE(ep_shellcode_thread)), &user_data, sizeof(user_data));

	
		printf("hijacking thread...\n");

		auto main_module = find_module(ctx, 0);
		printf("main_module 0x%llx...\n", main_module);

		auto main_dos_hd = read<IMAGE_DOS_HEADER>(ctx, main_module);
		auto main_nt_hd = read<IMAGE_NT_HEADERS64>(ctx, main_module + main_dos_hd.e_lfanew);
		auto main_ep = main_module + main_nt_hd.OptionalHeader.AddressOfEntryPoint;

		printf("main entry_point 0x%llx\n", main_ep);

		//mov rax 0xDEADBEEFDEADBEEF
		//jmp rax
		BYTE hookShellcode[] =
		{
			0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xE0
		};

		BYTE backupCode[sizeof(hookShellcode)];

		*(uintptr_t*)(hookShellcode + 2) = ctx.shellcode_ptr;

		read_memory(ctx, main_ep, backupCode, sizeof(backupCode));
		write_memory(ctx, main_ep, hookShellcode, sizeof(hookShellcode));
		

		CONTEXT thread_context = { 0 };
		thread_context.ContextFlags = CONTEXT_ALL;

		if (!GetThreadContext(ctx.target_thread, &thread_context))
		{
			printf("failed to set thread context...\n");
			return false;
		}
		ResumeThread(ctx.target_thread);
		//HANDLE thread = CreateRemoteThread(ctx.target_process, nullptr, 0, (LPTHREAD_START_ROUTINE)ctx.shellcode_ptr, NULL, 0, NULL);
		//if (!thread)
		//{
		//	printf("failed to start thread\n");
		//	return false;
		//}
		Sleep(1000);
		write_memory(ctx, main_ep, backupCode, sizeof(backupCode));


		printf("waiting for execution...\n");
		/*auto result = WaitForSingleObject(thread, 10000);
		CloseHandle(thread);*/


		ctx.result = result::success;
		printf("executed!\n");
		return true;
	}
	
	void inject(context& ctx)
	{
		if (!allocate_image(ctx))
		{
			ctx.result = result::image_allocation_failed;
			return;
		}

		if (!map_sections(ctx))
		{
			ctx.result = result::section_map_failed;
			return;
		}

		if (!ctx.opt.dont_resolve_relocs && !process_relocs(ctx))
		{
			ctx.result = result::relocating_failed;
			return;
		}

		if (!ctx.opt.dont_resolve_imports && !resolve_imports(ctx))
		{
			ctx.result = result::imports_failed;
			return;
		}

		call_entrypoint_thread(ctx);
	}
}