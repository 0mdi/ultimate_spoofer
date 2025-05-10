#include "windefs.hpp"
#include "piddb.hpp"

#include "dbglog.hpp"
#include "util.hpp"
#include "pattern_scanner.hpp"
#include "globals.hpp"
#include "imports.hpp"
#include "sk_crypter.hpp"

piddb piddb::inst;

bool piddb::init()
{
	util::module ntoskrnl;
	if (!util::get_module(skCrypt("ntoskrnl.exe"), ntoskrnl))
	{
		LOG("%s util::get_module failed", __FUNCTION__);
		return false;
	}

	LOG("ntoskrnl (%llx, %x)", ntoskrnl.base, ntoskrnl.size);
	//PATTERN_SET(ntoskrnl.base, ntoskrnl.size);

	//LOG("PIDDB | LOCK 1. TRY");
	//m_piddb_lock = (PERESOURCE)PATTERN_FIND_OFS_CODE("\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\x0D\x00\x00\x00\x00\x33\xDB", 3);
	//if (!m_piddb_lock)
	//{
	//	LOG("PIDDB | LOCK 2. TRY");
	//	m_piddb_lock = (PERESOURCE)PATTERN_FIND_OFS_CODE("\x48\x8D\x0D\x00\x00\x00\x00\x48\x83\x25\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00", 3);
	//	if (!m_piddb_lock)
	//	{
	//		LOG("PIDDB | LOCK 3. TRY");
	//		m_piddb_lock = (PERESOURCE)PATTERN_FIND_OFS_CODE("\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C\x24\x00\x00\x00\x00\x48\x8D\x4C\x24\x00", 3);
	//	}
	//}

	//LOG("PIDDB | TABLE 1. TRY");
	//m_piddb_table = (PRTL_AVL_TABLE)PATTERN_FIND_OFS_CODE("\x48\x8D\x0D\x00\x00\x00\x00\x4C\x89\x35\x00\x00\x00\x00\x49\x8B\xE9", 3);
	//if (!m_piddb_table)
	//{
	//	LOG("PIDDB | TABLE 2. TRY");
	//	m_piddb_table = (PRTL_AVL_TABLE)PATTERN_FIND_OFS_CODE("\x48\x8D\x0D\x00\x00\x00\x00\x48\x8B\xD0\xE8\x00\x00\x00\x00\x33\xD2", 3);
	//	if (!m_piddb_table)
	//	{
	//		LOG("PIDDB | TABLE 3. TRY");
	//		m_piddb_table = (PRTL_AVL_TABLE)PATTERN_FIND_OFS_CODE("\x48\x8D\x0D\x00\x00\x00\x00\x45\x33\xF6\x48\x89\x44\x24\x00\x0F\x11\x44\x24\x00", 3);
	//	}
	//}

	m_piddb_lock = (PERESOURCE)(ntoskrnl.base + globals::instance().args.PiDDBLock);
	m_piddb_table = (PRTL_AVL_TABLE)(ntoskrnl.base + globals::instance().args.PiDDBCacheTable);

	LOG("PIDDB (%llx, %llx)", m_piddb_lock, m_piddb_table);

	m_init = m_piddb_lock != NULL && m_piddb_table != NULL;
	return m_init;
}

bool piddb::clean()
{
	if (!m_init)
	{
		LOG("%s abort not initialized", __FUNCTION__);
		return false;
	}

	// enumerate tree first
	//LOG("BEFORE:");
	//for (auto p = RtlEnumerateGenericTableAvl(m_piddb_table, TRUE);
	//	p != NULL;
	//	p = RtlEnumerateGenericTableAvl(m_piddb_table, FALSE))
	//{
	//	auto entry = (PiDDBCacheEntry*)p;
	//	LOG("{%wZ, %llx, %llx)",
	//		entry->DriverName, entry->LoadStatus, entry->TimeDateStamp);
	//}

	auto& glob = globals::instance();

	// get the nt headers of the current driver
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)glob.driver_base;
	auto pNtHeaders = (PIMAGE_NT_HEADERS)((UINT64)glob.driver_base + pDosHeader->e_lfanew);

	// build a lookup entry
	PiDDBCacheEntry lookupEntry = { };
	lookupEntry.DriverName = glob.driver_name;
	lookupEntry.TimeDateStamp = pNtHeaders->FileHeader.TimeDateStamp;

	LOG("%wZ", &glob.driver_name);

	// acquire the ddb resource lock
	BOOLEAN AcquiredResource;
	CALL_RET(AcquiredResource, ExAcquireResourceExclusiveLite, m_piddb_lock, TRUE);
	LOG("%s: AcquiredResource: %i", __FUNCTION__, AcquiredResource);

	bool Result = false;

	// search our entry in the table
	PiDDBCacheEntry* pFoundEntry = nullptr;
	CALL_RET(pFoundEntry, RtlLookupElementGenericTableAvl, m_piddb_table, &lookupEntry);
	if (pFoundEntry)
	{
		LOG("Found Entry: (%wZ, %llx, %llx)", pFoundEntry->DriverName, pFoundEntry->LoadStatus, pFoundEntry->TimeDateStamp);
		LOG("%s: (%p) Unlinking PiDDBCacheTable...", __FUNCTION__, pFoundEntry);

		WCHAR* pFoundName = pFoundEntry->DriverName.Buffer;
		UINT32 pFoundNameLength = pFoundEntry->DriverName.Length;

		// first, unlink from the list
		BOOLEAN RemovedFromEntryList = RemoveEntryList(&pFoundEntry->List);
		// then delete the element from the avl table
		BOOLEAN DeletedAvlElement;
		CALL_RET(DeletedAvlElement, RtlDeleteElementGenericTableAvl, m_piddb_table, pFoundEntry);

		memset(pFoundName, 0, pFoundNameLength);
		CALL_NO_RET(ExFreePoolWithTag, pFoundName, 0);

		LOG("RemovedFRomEntryLst: %i, DeletedAvlElement: %p", RemovedFromEntryList, DeletedAvlElement);
		Result = true;
	}
	else
	{
		LOG("%s: Could not find entry in cachetable", __FUNCTION__);
	}

	// Check if its really removed
	if (Result)
	{
		PVOID element = nullptr;
		CALL_RET(element, RtlLookupElementGenericTableAvl, m_piddb_table, &lookupEntry);
		Result = element == NULL;
	}


	// release the ddb resource lock
	CALL_NO_RET(ExReleaseResourceLite, m_piddb_lock);

	return Result;
}