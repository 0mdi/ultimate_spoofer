#pragma once
#include "globals.hpp"

namespace spoofer::wmic
{
	DRIVER_STATUS cripple();

	extern UINT64 WmipInUseRegEntryHead;
}