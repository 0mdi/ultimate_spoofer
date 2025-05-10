
#include <ntddk.h>
#include <intrin.h>
#include <mmintrin.h>
#include "dbglog.hpp"
#include <ntimage.h>
#include <ntifs.h>
#include "ia32.hpp"
#include "um_km_com.hpp"

#define PFN_TO_PAGE(pfn) ( pfn << 12 )

namespace paging
{

	typedef union virtual_addr_
	{
		UINT64 value;
		void* pointer;
		struct
		{
			UINT64 offset : 12;
			UINT64 pt_index : 9;
			UINT64 pd_index : 9;
			UINT64 pdpt_index : 9;
			UINT64 pml4_index : 9;
			UINT64 reserved : 16;
		};
	} virtual_addr;


	class process_ctx
	{
	public:


		process_ctx() = default;

		process_ctx(com::com_ctx* ctx, PEPROCESS eprocess)
		{
			this->ctx_ = ctx;
			attach(eprocess);
		}

		~process_ctx()
		{
			detach();
		}

		uint64_t get_user_dirbase(PEPROCESS eprocess) const
		{
			uint64_t dir = 0;

			LOG("EPROCESS: 0x%llX", eprocess);

			auto dirbase = *(uint64_t*)((uintptr_t)eprocess + /*g_args->ofs.EProcess_DirTableBase*/0x28);
			auto user_dir_base = *(uint64_t*)((uintptr_t)eprocess + /*g_args->ofs.EProcess_UserDirTableBase*/0x388);

			LOG("dirbase 0x%llX", dirbase);
			LOG("user_dir_base 0x%llX", user_dir_base);



			if (dirbase)
				dir = dirbase;
			else if (user_dir_base)
				dir = user_dir_base;

			//ObDereferenceObject(proc);
	
			return dir;
		}

		bool attach()
		{
			if (attached())
				detach();

			eprocess_ = 0;
			dirbase_ = __readcr3();
			dirbase_ &= ~0xF;
			attached_ = true;
			return true;
		}

		bool attach(PEPROCESS eprocess)
		{
			if (attached())
				detach();

			eprocess_ = eprocess;
			dirbase_ = get_user_dirbase(eprocess);
			if (dirbase_)
			{
				dirbase_ &= ~0xF;
				attached_ = true;
				return true;
			}

			return false;
		}

		void detach()
		{
			if (attached_)
			{
				dirbase_ = 0;
				attached_ = false;
			}
		}

		bool attached()
		{
			return attached_;
		}

		SIZE_T read_physical(uintptr_t addr, uint8_t* buffer, size_t len) const
		{
			MM_COPY_ADDRESS phys_addr = { 0 };
			phys_addr.PhysicalAddress.QuadPart = addr;
			SIZE_T bytes_read = 0;

			if (NT_SUCCESS(ctx_->_MmCopyMemory((PVOID)buffer, phys_addr, len, MM_COPY_MEMORY_PHYSICAL, &bytes_read)))
			{
				return bytes_read;
			}
			return 0;
		}

		SIZE_T write_physical(uintptr_t addr, uint8_t* buffer, size_t len) const
		{
			PHYSICAL_ADDRESS phys_addr = { 0 };
			phys_addr.QuadPart = addr;

			PVOID pmapped_mem = ctx_->_MmMapIoSpaceEx(phys_addr, len, PAGE_READWRITE);

			if (!pmapped_mem)
				return 0;

			//memcpy(pmapped_mem, buffer, len);
			__movsb((PUCHAR)pmapped_mem, (PUCHAR)buffer, len);

			ctx_->_MmUnmapIoSpace(pmapped_mem, len);
			return len;
		}

		template<class T>
		T read_physical(uintptr_t addr) const
		{
			T val{};
			read_physical(addr, (uint8_t*)&val, sizeof(T));
			return val;
		}

		template<class T>
		void write_physical(uintptr_t addr, const T& val) const
		{
			write_physical(addr, (uint8_t*)&val, sizeof(T));
		}

		pml4e_64 get_pml4e(unsigned int index) const
		{
			return read_physical<pml4e_64>(dirbase_ + sizeof(pml4e_64) * index);
		}

		pdpte_64 get_pdpte(const pml4e_64& pml4e, unsigned int index) const
		{
			return read_physical<pdpte_64>(PFN_TO_PAGE(pml4e.page_frame_number) + sizeof(pdpte_64) * index);
		}

		pde_64 get_pde(const pdpte_64& pdpte, unsigned int index) const
		{
			return read_physical<pde_64>(PFN_TO_PAGE(pdpte.page_frame_number) + sizeof(pde_64) * index);
		}
		 
		pte_64 get_pte(const pde_64& pde, unsigned int index) const
		{
			return read_physical<pte_64>(PFN_TO_PAGE(pde.page_frame_number) + sizeof(pte_64) * index);
		}

		void set_pdpte(const pml4e_64& pml4e, unsigned int index, pdpte_64& pdpte)
		{
			write_physical<pdpte_64>(PFN_TO_PAGE(pml4e.page_frame_number) + sizeof(pdpte_64) * index, pdpte);
		}

		template<class T>
		bool read_virtual(uintptr_t virtual_address, T& value) const
		{
			return read_virtual(virtual_address, &value, sizeof(T));
		}

		template<class T>
		bool write_virtual(uintptr_t virtual_address, const T& value)
		{
			return write_virtual(virtual_address, (void*)&value, sizeof(T));
		}

		bool read_virtual(uintptr_t virtual_address, void* buffer, size_t size) const
		{
			size_t offset = 0;
			size_t size_left = size;

			uintptr_t current_addr = virtual_address;
			while (true)
			{
				size_t page_size = 0;
				uintptr_t page_offset = 0;

				uintptr_t pa = virt_to_phys(current_addr, &page_size, &page_offset);
				if (!pa)
				{
					LOG("translate fail 0x%llx", current_addr);
					return false;
				}
				auto page_read_data_size = page_size - page_offset;
				if (page_read_data_size > size_left)
					page_read_data_size = size_left;

				LOG("performing partial read va @ 0x%llx offset 0x%llX size 0x%llX", current_addr, page_offset, page_read_data_size);

				if (read_physical(pa, ((uint8_t*)buffer) + offset, page_read_data_size) <= 0)
				{
					LOG("read fail");
					return false;
				}

				offset += page_read_data_size;
				size_left -= page_read_data_size;

				if (size_left == 0)
					break;

				current_addr += page_read_data_size;
			}
			return true;
		}
		bool write_virtual(uintptr_t virtual_address, void* buffer, size_t size)
		{
			size_t offset = 0;
			size_t size_left = size;

			uintptr_t current_addr = virtual_address;
			while (true)
			{
				size_t page_size = 0;
				uintptr_t page_offset = 0;

				uintptr_t pa = virt_to_phys(current_addr, &page_size, &page_offset);
				if (!pa)
				{
					LOG("translate fail 0x%llx", current_addr);
					return false;
				}

				auto page_write_data_size = page_size - page_offset;
				if (page_write_data_size > size_left)
					page_write_data_size = size_left;

				LOG("performing partial write va @ 0x%llx offset 0x%llX size 0x%llX", current_addr, page_offset, page_write_data_size);

				if (write_physical(pa, ((uint8_t*)buffer) + offset, page_write_data_size) <= 0)
				{
					LOG("write fail");
					return false;
				}

				offset += page_write_data_size;
				size_left -= page_write_data_size;

				if (size_left == 0)
					break;

				current_addr += page_write_data_size;
			}
			return true;
		}
		//Intel IA32 Manual Volume 3 / 4.5 
		uintptr_t virt_to_phys(uintptr_t virtual_address, size_t* page_size = nullptr, uint64_t* offset = nullptr) const
		{
			virtual_addr va{ virtual_address };


			auto pml4e = get_pml4e(va.pml4_index);
			if (!pml4e.present)
			{
				LOG("pml4e not present");
				return 0;
			}

			auto pdpte = get_pdpte(pml4e, va.pdpt_index);
			if (!pdpte.present)
			{
				LOG("pdpte 0");
				return 0;
			}

			//maps 1GB
			if (pdpte.large_page)
			{
				LOG("1GB Page");
				if (page_size)
					*page_size = 0x40000000;


				if (offset)
					*offset = (virtual_address & ~(~0ull << 30));

				return (pdpte.flags & (~0ull << 42 >> 12)) + (virtual_address & ~(~0ull << 30));
			}

			auto pde = get_pde(pdpte, va.pd_index);
			if (!pde.present)
			{
				LOG("pde not present");
				return 0;
			}

			//maps 2MB
			if (pde.large_page)
			{
				if (page_size)
					*page_size = 0x200000;

				if (offset)
					*offset = (virtual_address & ~(~0ull << 21));

				return PFN_TO_PAGE(pde.page_frame_number) + (virtual_address & ~(~0ull << 21));
			}

			auto pte = get_pte(pde, va.pt_index);
			if (!pte.present)
			{
				LOG("pte not present 0x%llx", pte.page_frame_number);
				return 0;
			}
			if (page_size)
				*page_size = 0x1000;

			if (offset)
				*offset = va.offset;
			//maps 4KB 
			return PFN_TO_PAGE(pte.page_frame_number) + va.offset;
		}


		uint64_t get_dirbase() const
		{
			return dirbase_;
		}

	private:
		bool attached_ = false;
		PEPROCESS eprocess_ = 0;
		uint64_t dirbase_ = 0;
		com::com_ctx* ctx_ = 0;
	};

}