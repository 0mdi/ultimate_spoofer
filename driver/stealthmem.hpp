#pragma once
#include "inttypes.hpp"
#include "globals.hpp"
#include "imports.hpp"
#include "util.hpp"
#include "sk_crypter.hpp"

namespace stealth
{
	// Thanks can1357
#define PFN_TO_PAGE(pfn) ( pfn << 12 )

#pragma pack(push, 1)
	typedef union CR3_
	{
		uint64_t value;
		struct
		{
			uint64_t ignored_1 : 3;
			uint64_t write_through : 1;
			uint64_t cache_disable : 1;
			uint64_t ignored_2 : 7;
			uint64_t pml4_p : 40;
			uint64_t reserved : 12;
		};
	} PTE_CR3;


	typedef union VIRT_ADDR_
	{
		uint64_t value;
		void* pointer;
		struct
		{
			uint64_t offset : 12;
			uint64_t pt_index : 9;
			uint64_t pd_index : 9;
			uint64_t pdpt_index : 9;
			uint64_t pml4_index : 9;
			uint64_t reserved : 16;
		};
	} VIRT_ADDR;

	typedef union PDPTE_
	{
		uint64_t value;
		struct
		{
			uint64_t present : 1;
			uint64_t rw : 1;
			uint64_t user : 1;
			uint64_t write_through : 1;
			uint64_t cache_disable : 1;
			uint64_t accessed : 1;
			uint64_t dirty : 1;
			uint64_t page_size : 1;
			uint64_t ignored_2 : 4;
			uint64_t pd_p : 40;
			uint64_t ignored_3 : 11;
			uint64_t xd : 1;
		};
	} PDPTE;

	typedef union PDE_
	{
		uint64_t value;
		struct
		{
			uint64_t present : 1;
			uint64_t rw : 1;
			uint64_t user : 1;
			uint64_t write_through : 1;
			uint64_t cache_disable : 1;
			uint64_t accessed : 1;
			uint64_t dirty : 1;
			uint64_t page_size : 1;
			uint64_t ignored_2 : 4;
			uint64_t pt_p : 40;
			uint64_t ignored_3 : 11;
			uint64_t xd : 1;
		};
	} PDE;

	typedef union PTE_
	{
		uint64_t value;
		VIRT_ADDR vaddr;
		struct
		{
			uint64_t present : 1;
			uint64_t rw : 1;
			uint64_t user : 1;
			uint64_t write_through : 1;
			uint64_t cache_disable : 1;
			uint64_t accessed : 1;
			uint64_t dirty : 1;
			uint64_t pat : 1;
			uint64_t global : 1;
			uint64_t ignored_1 : 3;
			uint64_t page_frame : 40;
			uint64_t ignored_3 : 11;
			uint64_t xd : 1;
		};
	} PTE;
#pragma pack(pop)

	typedef union PML4E_
	{
		uint64_t value;
		struct
		{
			uint64_t present : 1;
			uint64_t rw : 1;
			uint64_t user : 1;
			uint64_t write_through : 1;
			uint64_t cache_disable : 1;
			uint64_t accessed : 1;
			uint64_t ignored_1 : 1;
			uint64_t reserved_1 : 1;
			uint64_t ignored_2 : 4;
			uint64_t pdpt_p : 40;
			uint64_t ignored_3 : 11;
			uint64_t xd : 1;
		};
	} PML4E;

	struct page_table_info
	{
		PML4E* Pml4e;
		PDPTE* Pdpte;
		PDE* Pde;
		PTE* Pte;
	};

	typedef uint64_t PHYS_ADDR;

	__forceinline page_table_info query_page_table(void* va)
	{
		page_table_info pi = { 0, 0, 0, 0 };
		VIRT_ADDR addr = { (uint64_t)va };

		uint64_t cur_process = 0;
		CALL_RET(cur_process, PsGetCurrentProcess);
		if (!cur_process)
			return pi;

		auto target_dir_base = *(uint64_t*)(cur_process + globals::instance().args.DirectoryTableBase);
		PTE_CR3 cr3 = { target_dir_base };

		{
			uint64_t a = PFN_TO_PAGE(cr3.pml4_p) + sizeof(PML4E) * addr.pml4_index;

			PHYSICAL_ADDRESS _a;
			_a.QuadPart = a;

			PVOID b = nullptr;
			CALL_RET(b, MmGetVirtualForPhysical, _a);

			BOOLEAN is_valid = FALSE;
			CALL_RET(is_valid, MmIsAddressValid, b);

			if (b && !is_valid)
				return pi;

			PML4E& e = *(PML4E*)(b);
			if (!e.present)
				return pi;
			pi.Pml4e = &e;
		}
		{
			uint64_t a = PFN_TO_PAGE(pi.Pml4e->pdpt_p) + sizeof(PDPTE) * addr.pdpt_index;

			PHYSICAL_ADDRESS _a;
			_a.QuadPart = a;

			PVOID b = nullptr;
			CALL_RET(b, MmGetVirtualForPhysical, _a);

			BOOLEAN is_valid = FALSE;
			CALL_RET(is_valid, MmIsAddressValid, b);

			if (b && !is_valid)
				return pi;

			PDPTE& e = *(PDPTE*)(b);
			if (!e.present)
				return pi;
			pi.Pdpte = &e;
		}
		{
			uint64_t a = PFN_TO_PAGE(pi.Pdpte->pd_p) + sizeof(PDE) * addr.pd_index;

			PHYSICAL_ADDRESS _a;
			_a.QuadPart = a;

			PVOID b = nullptr;
			CALL_RET(b, MmGetVirtualForPhysical, _a);

			BOOLEAN is_valid = FALSE;
			CALL_RET(is_valid, MmIsAddressValid, b);

			if (b && !is_valid)
				return pi;

			PDE& e = *(PDE*)(b);
			if (!e.present)
				return pi;
			pi.Pde = &e;
			if (pi.Pde->page_size)
				return pi;
		}
		{
			uint64_t a = PFN_TO_PAGE(pi.Pde->pt_p) + sizeof(PTE) * addr.pt_index;

			PHYSICAL_ADDRESS _a;
			_a.QuadPart = a;
			PVOID b = nullptr;
			CALL_RET(b, MmGetVirtualForPhysical, _a);

			BOOLEAN is_valid = FALSE;
			CALL_RET(is_valid, MmIsAddressValid, b);

			if (b && !is_valid)
				return pi;

			PTE& e = *(PTE*)(b);
			if (!e.present)
				return pi;
			pi.Pte = &e;
		}
		return pi;
	}

	__forceinline uint64_t alloc_independent(size_t size)
	{
		util::module ntos;
		if (!util::get_module(skCrypt("ntoskrnl.exe"), ntos))
			return 0;

		using MmAllocateIndependentPages_t = uint64_t(*)(SIZE_T, ULONG);
		auto fn = (MmAllocateIndependentPages_t)(ntos.base + globals::instance().args.MmAllocateIndependentPages);

		KIRQL old_irql;
		CALL_RET(old_irql, KfRaiseIrql, PASSIVE_LEVEL);

		auto allocated_pages = fn(size, -1);
		CALL_NO_RET(KeLowerIrql, old_irql);

		if (!allocated_pages)
			return 0;

		memset((void*)allocated_pages, 0, size);
		auto page_start = (uint8_t*)(allocated_pages & (~0xFFF));
		auto page_end = (uint8_t*)(((allocated_pages + size) & (~0xFFF)) + 0x1000);

		for (auto page = page_start; page < page_end;)
		{
			auto tbl = query_page_table(page);
			if (tbl.Pte)
			{
				tbl.Pte->xd = FALSE;
				page += 0x1000;
			}
			else if (tbl.Pde)
			{
				tbl.Pde->xd = FALSE;
				page += 0x200000;
			}
			else
			{
				return 0;
			}
		}
		return allocated_pages;
	}
}