#include <ntifs.h>
#include "wmic.hpp"
#include "util.hpp"
#include "dbglog.hpp"
#include "sk_crypter.hpp"
#include "util.hpp"

// test
#include <ntifs.h>

extern "C"
{
	extern POBJECT_TYPE* IoDriverObjectType;
}

namespace spoofer::wmic
{
	UINT64	WmipInUseRegEntryHead = 0,
			WmipWmiLibInfo = 0,
			WmipGuidListUnkPtr = 0,
			WmipMRHeadPtr = 0,
			WmipDSHeadPtr = 0,
			WmipGEHeadPtr = 0;

	DRIVER_STATUS cripple()
	{
		util::module ntos;
		if (!util::get_module(skCrypt("ntoskrnl.exe"), ntos))
			return DRIVER_STATUS::NTOS_IMPORT_ERROR;
		
		auto& glob = globals::instance();
		if (!glob.args.WmipInUseRegEntryHead)
			return DRIVER_STATUS::NTOS_NOT_FOUND;

		WmipInUseRegEntryHead = (ntos.base + glob.args.WmipInUseRegEntryHead);

		if (*(UINT64*)WmipInUseRegEntryHead == WmipInUseRegEntryHead)
			return DRIVER_STATUS::ALREADY_LOADED;

		*(UINT64*)WmipInUseRegEntryHead = WmipInUseRegEntryHead;
		
		// .PAGE code
		//*(UINT64*)WmipGuidListUnkPtr = 0;
		//uint64_t null_qword = 0;
		//util::memcpy_protected((void*)WmipGuidListUnkPtr, &null_qword, sizeof(null_qword));

		// now make it completely insane
		// \\Device\\WMIDataDevice
		// WMIxWDM
		// maybe abuse KseDsCallbackHookIrpFunction


		LOG("WMIC crippled successfully!");

		return DRIVER_STATUS::SUCCESS;
	}
}