#include "spoofer.hpp"
#include "gpu.hpp"
#include "stealthmem.hpp"
#include "sk_crypter.hpp"
#include "util.hpp"
#include "pattern_scanner.hpp"
#include "dbglog.hpp"

extern "C"
{
	extern POBJECT_TYPE* IoDriverObjectType;
}


namespace spoofer::gpu
{

	DRIVER_STATUS spoof()
	{
		util::module nvlddmkm;
		if (!util::get_module(skCrypt("nvlddmkm.sys"), nvlddmkm))
		{
			LOG("failed to get nvlddmkm.sys");
			return NVIDIA_DRIVER_NOT_FOUND;

		}

		LOG("nvlddmkm: %p, %x", nvlddmkm.base, nvlddmkm.size);

		PATTERN_SET(nvlddmkm.base, nvlddmkm.size);
		auto important_func = (uint64_t)PATTERN_FIND_CODE("\x48\x8B\x05\x00\x00\x00\x00\x33\xD2\x44\x8B\xC9\x48\x8B\x80\x00\x00\x00\x00\x44\x8B\x80\x00\x00\x00\x00\x45\x85\xC0\x74\x1F\x48\x05\x00\x00\x00\x00\x44\x39\x48\x08\x75\x08\x48\x8B\x08\x48\x85\xC9\x75\x0E");
		if (!important_func)
		{
			LOG("failed to pattern scan for important func");
			return NVIDIA_PATTERN_NOT_FOUND;
		}

		auto unk_list_ptr = *(uint32_t*)(important_func + 3) + important_func + 7;
		LOG("important_func: %p, unk_list_ptr: %p", important_func, unk_list_ptr);
		
		BOOLEAN list_valid = FALSE;
		CALL_RET(list_valid, MmIsAddressValid, (PVOID)unk_list_ptr);
		if (!list_valid)
		{
			LOG("unknown list is not valid");
			return NVIDIA_LIST_NOT_VALID;
		}

		auto unk_list = *(uint64_t*)unk_list_ptr;
		list_valid = FALSE;
		CALL_RET(list_valid, MmIsAddressValid, (PVOID)unk_list);
		if (!list_valid)
		{
			LOG("unknown list is not valid");
			return NVIDIA_LIST_NOT_VALID;
		}

		LOG("unk_list: %p", unk_list);

		auto v2 = *(uint64_t*)(unk_list + 0x1B8);
		if (v2)
		{
			auto v3 = *(uint32_t*)(v2 + 0x1B9B0);
			if (v3)
			{
				LOG("v3: %i (count)", v3);
				auto v4 = v2 + 0x1B7B0;
				auto v1 = 0;
				LOG("v4: %p", v4);
				while (v1 < v3)
				{
					auto v5 = *(uint64_t*)v4;
					LOG("v5: %p", v5);
					BOOLEAN is_valid = FALSE;
					CALL_RET(is_valid, MmIsAddressValid, (PVOID)v5);
					if (is_valid)
					{
						auto GpuSerialInfo = *(uint64_t*)(v5 + 0x80);
						LOG("GpuSerialInfo: %p", GpuSerialInfo);
						if (GpuSerialInfo)
						{
							LOG("NVRM: GPU at PCI:%04x:%02x:%02x",
								*(uint64_t*)(GpuSerialInfo + 0x970) >> 32,
								*(unsigned __int8*)(GpuSerialInfo + 0x971),
								*(unsigned __int8*)(GpuSerialInfo + 0x970))

							auto SerialStruct = *(uint64_t*)(GpuSerialInfo + 0x2598);
							LOG("SerialStruct: %p", SerialStruct);
							if (SerialStruct)
							{
								auto serialptr = *(uint64_t*)(SerialStruct + 0x1C);
								LOG("SerialStruct: %p, serialptr: %p", SerialStruct, serialptr);
							}
						}
					}

					++v1;
					v4 += 16;
				}
			}
		}

		return SUCCESS;
	}
}