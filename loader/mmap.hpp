#pragma once

#include <Windows.h>
#include <cstdint>

namespace mmap
{
#include <pshpack1.h>

	struct mmap_user_data
	{
		uint32_t			magic_value;
		uint32_t			shellcode_size;
		char				hdd_serial[96];
		uint8_t				is_executed;
		uintptr_t			module_base;
		uint32_t			image_size;
		uint32_t			full_size;
		uintptr_t			expire_seconds;
	};


	struct options
	{
		bool				use_page_hide;
		bool				suspend_while_inject;
		uint64_t			injection_delay;

		bool				dont_resolve_imports;
		bool				dont_resolve_relocs;
		bool				dont_fix_stack_cookie;

		uintptr_t			overwrite_executor_ptr;

		size_t				required_module_count;
		char				required_modules[100][10];
	};

	enum class result
	{
		success,
		loaded_without_execute,
		ntdll_not_found,
		executor_not_found,
		invalid_pid,
		required_module_missing,
		invalid_image,
		invalid_target_proc,
		unknown_error,
		kernel_module_not_found,
		image_allocation_failed,
		section_map_failed,
		relocating_failed,
		out_of_memory,
		imports_failed,
	};

#include <poppack.h>
	struct context
	{
		uintptr_t			pe_image;
		size_t				pe_image_len;
		PIMAGE_NT_HEADERS	pe_image_nt;
		PIMAGE_DOS_HEADER	pe_image_dos;


		uint32_t			target_pid;
		HANDLE				target_process;
		HANDLE				target_thread;

		uintptr_t			image_base;
		uintptr_t			shellcode_ptr;
		size_t				shellcode_size;
		size_t				region_size;

		options				opt;
		result				result;

		uintptr_t			executor_ptr;
	};

	bool	prepare(context& ctx, options& options, uint32_t pid, uintptr_t pe_image, size_t pe_image_len);
	void	inject(context& ctx);
	void	cleanup(context& ctx);
}