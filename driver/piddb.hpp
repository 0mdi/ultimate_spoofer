#pragma once
#include <ntdef.h>

struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
};

class piddb
{
private:
	static piddb inst;

	bool m_init;

	PERESOURCE m_piddb_lock;
	PRTL_AVL_TABLE m_piddb_table;

public:
	static piddb& instance()
	{
		return inst;
	}

	bool init();
	bool clean();
};