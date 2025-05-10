#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string>
#include <filesystem>
#include <vector>
#include <tuple>
#include <algorithm>
#include <random>
#include <fstream>

#include "../x64/Release/driver.hpp"

#include "mmap.hpp"
#include "globals.hpp"
#include "pdb.hpp"
#include "registry.h"
// cheat binary
#include "wmic.hpp"


#pragma comment(lib, "ntdll.lib")

#include <pshpack1.h>
struct driver_args_t
{
	uint32_t MmAllocateIndependentPages = 0;
	uint32_t PiDDBLock = 0;
	uint32_t PiDDBCacheTable = 0;
	uint32_t DirectoryTableBase = 0;
	uint32_t UserDirectoryTableBase = 0;
	uint32_t g_KernelHashBucketList = 0;
	uint32_t g_HashCacheLock = 0;
	uint32_t KseEngine = 0;
	uint32_t SrbShim = 0;
	uint32_t DeviceIdShim = 0;
	uint32_t ATADeviceIdShim = 0;
	uint32_t SrbShimHookDeviceControl = 0;
	uint32_t DeviceIdShimHookDeviceControl = 0;
	uint32_t ATADeviceIdShimHookDeviceControl = 0;
	uint32_t RaDriverDeviceControlIrp = 0;
	uint32_t WmipInUseRegEntryHead = 0;
	uint32_t SrbShimStorageAdapterPropertyCompletionHook = 0;
	uint32_t DeviceIdShimStorageDeviceIdCompletionHook = 0;
	uint32_t KseSetCompletionHook = 0;
	//uint32_t ndisDummyIrpHandler = 0;
	uint8_t  SpoofHash[16];
};
#include <poppack.h>

std::vector<uint8_t> file2bin(const std::string& path)
{
	std::ifstream fs(path, std::ios::binary);
	if (!fs)
		return {};

	fs.seekg(0, std::ios::end);
	auto size = fs.tellg();
	fs.seekg(0, std::ios::beg);

	std::vector<uint8_t> res;
	res.resize(size);

	fs.read((char*)res.data(), size);

	return res;
}
bool bin2file(const std::wstring& path, uint8_t* binary, size_t len)
{
	std::ofstream os(path, std::ios::binary | std::ios::trunc);
	if (!os)
		return false;

	os.write((const char*)binary, len);
	auto tp = os.tellp();

	return tp == len;
}

/************************************************************************/
/* 1. Load driver                                                       */
/************************************************************************/
bool prepare_registry(driver_args_t* driver_args)
{
	auto g = globals::instance();
	HKEY driver_root_key;
	char driver_registry_key[1000];

	sprintf_s<sizeof(driver_registry_key)>(driver_registry_key, "%s%s", "SYSTEM\\CurrentControlSet\\Services\\", g->driver_name.c_str());
	
	if (RegCreateKeyA(HKEY_LOCAL_MACHINE, driver_registry_key, &driver_root_key) == ERROR_SUCCESS)
	{
		auto driver_path = "\\??\\" + g->driver_path;

		uint32_t service_type = 1;
		uint32_t service_error_control = 1;
		uint32_t service_start = 3;

		if (RegSetValueExA(driver_root_key, "ImagePath", 0, REG_EXPAND_SZ, (const BYTE*)driver_path.c_str(), driver_path.length() + 1) == ERROR_SUCCESS)
		{
			if (RegSetValueExA(driver_root_key, ("Start"), 0, REG_DWORD, (const BYTE*)&service_start, sizeof(service_start)) == ERROR_SUCCESS)
			{
				if (RegSetValueExA(driver_root_key, ("Type"), 0, REG_DWORD, (const BYTE*)&service_type, sizeof(service_type)) == ERROR_SUCCESS)
				{
					if (RegSetValueExA(driver_root_key, ("ErrorControl"), 0, REG_DWORD, (const BYTE*)&service_error_control, sizeof(service_error_control)) == ERROR_SUCCESS)
					{
						if (driver_args)
						{
							if ((RegSetValueExW(driver_root_key, L"data", 0, REG_BINARY, (const BYTE*)driver_args, (DWORD)sizeof(driver_args_t))))
								return false;
						}


						RegCloseKey(driver_root_key);
						return true;
					}
				}
			}
		}

		// worst cast cleanup
		RegCloseKey(driver_root_key);
	}

	printf("[-] error in registry preparation routines\n");
	return false;
}

bool clean_registry()
{
	char registry_key[ 1000 ];
	sprintf_s<1000>( registry_key, "%s%s", ( "SYSTEM\\CurrentControlSet\\Services\\" ), globals::instance()->driver_name );

	return RegDeleteKeyA( HKEY_LOCAL_MACHINE, registry_key ) == ERROR_SUCCESS;
}
std::string gen_random(const int len) 
{

	std::string tmp_s;
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	tmp_s.reserve(len);

	for (int i = 0; i < len; ++i)
		tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

	return tmp_s;

}
bool load_driver(driver_args_t* driver_args)
{
	auto g = globals::instance();

	std::wstring wpath(g->driver_path.begin(), g->driver_path.end());

	if (!bin2file(wpath, getdriver(), getdriverLen()))
		return false;

	if (!std::filesystem::exists(g->driver_path))
	{
		printf("[-] file %s does not exist\n", g->driver_path.c_str());
		return false;
	}
	
	// 1. prepare registry
	if (prepare_registry(driver_args))
	{
		// 2. privileges
		auto enable_privileges = [&](const wchar_t* privilege_name) -> bool
		{
			TOKEN_PRIVILEGES Privilege;
			HANDLE hToken;

			Privilege.PrivilegeCount = 1;
			Privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (!LookupPrivilegeValueW(NULL, privilege_name/*L"SeLoadDriverPrivilege"*/,
				&Privilege.Privileges[0].Luid))
				return false;

			if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_ADJUST_PRIVILEGES, &hToken))
				return false;

			if (!AdjustTokenPrivileges(hToken, FALSE, &Privilege, sizeof(Privilege),
				NULL, NULL)) {
				CloseHandle(hToken);
				return false;
			}

			CloseHandle(hToken);
			return true;
		};

		if (!enable_privileges( L"SeLoadDriverPrivilege" ))
		{
			if ( !clean_registry() )
				printf( "[-] failed to clean registry!\n" );

			printf("[-] failed to enable privileges\n");
			std::filesystem::remove(g->driver_path);
			return false;
		}

		// 3. ntloaddriver
		using tNtLoadDriver = NTSTATUS(NTAPI*)(PUNICODE_STRING);
		auto NtLoadDriver = (tNtLoadDriver)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");

		if (!NtLoadDriver)
		{
			if ( !clean_registry() )
				printf( "[-] failed to clean registry!\n" );

			printf("[-] cannot resolve ntloaddriver\n");
			std::filesystem::remove(g->driver_path);
			return false;
		}

		wchar_t registry_key[1000];
		UNICODE_STRING uregistry_key;
		std::wstring driver_name(g->driver_name.begin(), g->driver_name.end());
		wsprintfW(registry_key, L"%s%s", L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\", driver_name.c_str());

		printf( "[+] registry key: %ws\n", registry_key );
		RtlInitUnicodeString(&uregistry_key, registry_key);
		NTSTATUS status = NtLoadDriver(&uregistry_key);

		printf("[+] ntloaddriver status: %lx\n", status);

		if ( !clean_registry() )
			printf( "[-] failed to clean registry!\n" );

		std::filesystem::remove(g->driver_path);
		return true;
	}

	printf("[-] error while (%s) aborting...\n", __FUNCTION__);
	std::filesystem::remove(g->driver_path);
	return false;
}

std::string get_system_dir()
{
	std::string dir;
	dir.resize(255);
	dir.resize(GetSystemDirectoryA(dir.data(), 255));
	return dir;
}

bool get_pdb_info(driver_args_t& pdb_info)
{
	try
	{
		auto system_dir = get_system_dir();

		auto ntoskrnl_info = pdb::get_download_info(system_dir + "\\ntoskrnl.exe");
		auto ci_info = pdb::get_download_info(system_dir + "\\ci.dll");
		auto win32kfull_info = pdb::get_download_info(system_dir + "\\win32kfull.sys");
		auto win32kbase_info = pdb::get_download_info(system_dir + "\\win32kbase.sys");
		auto ahcache_info = pdb::get_download_info(system_dir + "\\drivers\\ahcache.sys");
		auto storport_info = pdb::get_download_info(system_dir + "\\drivers\\storport.sys");
		auto ndis_info = pdb::get_download_info(system_dir + "\\drivers\\ndis.sys");

		if (!ntoskrnl_info.has_value() || !ci_info.has_value() || 
			!win32kfull_info.has_value() || !ahcache_info.has_value() ||
			!win32kbase_info.has_value() || !storport_info.has_value() || 
			!ndis_info.has_value())
		{
			printf("failed to get needed drivers...\n");
			return false;
		}


		auto request = pdb::create_request();

		auto ntoskrnl = request->add_entry(ntoskrnl_info.value());
		ntoskrnl->add_symbol("MmAllocateIndependentPages", &pdb_info.MmAllocateIndependentPages);
		ntoskrnl->add_symbol("PiDDBLock", &pdb_info.PiDDBLock);
		ntoskrnl->add_symbol("PiDDBCacheTable", &pdb_info.PiDDBCacheTable);
		ntoskrnl->add_symbol("KseEngine", &pdb_info.KseEngine);
		ntoskrnl->add_symbol("WmipInUseRegEntryHead", &pdb_info.WmipInUseRegEntryHead);
		ntoskrnl->add_symbol("KseSetCompletionHook", &pdb_info.KseSetCompletionHook);

		auto kprocess = ntoskrnl->add_type("_KPROCESS");
		kprocess->add_member("DirectoryTableBase", &pdb_info.DirectoryTableBase);
		kprocess->add_member("UserDirectoryTableBase", &pdb_info.UserDirectoryTableBase);


		auto ci = request->add_entry(ci_info.value());
		ci->add_symbol("g_KernelHashBucketList", &pdb_info.g_KernelHashBucketList);
		ci->add_symbol("g_HashCacheLock", &pdb_info.g_HashCacheLock);

		auto storport = request->add_entry(storport_info.value());
		storport->add_symbol("SrbShim", &pdb_info.SrbShim);
		storport->add_symbol("DeviceIdShim", &pdb_info.DeviceIdShim);
		storport->add_symbol("ATADeviceIdShim", &pdb_info.ATADeviceIdShim);
		storport->add_symbol("SrbShimHookDeviceControl", &pdb_info.SrbShimHookDeviceControl);
		storport->add_symbol("DeviceIdShimHookDeviceControl", &pdb_info.DeviceIdShimHookDeviceControl);
		storport->add_symbol("ATADeviceIdShimHookDeviceControl", &pdb_info.ATADeviceIdShimHookDeviceControl);
		storport->add_symbol("RaDriverDeviceControlIrp", &pdb_info.RaDriverDeviceControlIrp);
		storport->add_symbol("SrbShimStorageAdapterPropertyCompletionHook", &pdb_info.SrbShimStorageAdapterPropertyCompletionHook);
		storport->add_symbol("DeviceIdShimStorageDeviceIdCompletionHook", &pdb_info.DeviceIdShimStorageDeviceIdCompletionHook);

		//auto ndis = request->add_entry(ndis_info.value());
		//ndis->add_symbol("?ndisDummyIrpHandler@@YAJPEAU_DEVICE_OBJECT@@PEAU_IRP@@@Z", &pdb_info.ndisDummyIrpHandler);

		pdb::get(request);
		return true;
	}
	catch (std::exception& e)
	{
		printf("unhandled exception: %s\n", e.what());
		return false;
	}
}

int main(int argc, char** argv)
{
	srand(GetTickCount());
	auto g = globals::instance();

	driver_args_t driver_args;
	printf("downloading pdb info...\n");
	if (!get_pdb_info(driver_args))
	{
		printf("[-] failed to receive PDB info\n");
		getchar();
		return 1;
	}

	printf("%-40s = 0x%08X\n", "MmAllocateIndependentPages", driver_args.MmAllocateIndependentPages);
	printf("%-40s = 0x%08X\n", "PiDDBLock", driver_args.PiDDBLock);
	printf("%-40s = 0x%08X\n", "PiDDBCacheTable", driver_args.PiDDBCacheTable);
	printf("%-40s = 0x%08X\n", "DirectoryTableBase", driver_args.DirectoryTableBase);
	printf("%-40s = 0x%08X\n", "UserDirectoryTableBase", driver_args.UserDirectoryTableBase);
	printf("%-40s = 0x%08X\n", "g_KernelHashBucketList", driver_args.g_KernelHashBucketList);
	printf("%-40s = 0x%08X\n", "g_HashCacheLock", driver_args.g_HashCacheLock);

	getchar();

	std::string application_name = argv[0];
	application_name = application_name.substr(application_name.find_last_of('\\') + 1);

	g->application_name = application_name;
	g->application_path = std::filesystem::current_path().string();

	g->driver_path = g->application_path + std::string("\\") + gen_random((rand() % 10) + 10) + ".sys";
	g->driver_name = gen_random((rand() % 10) + 8);

	printf("[!] application_path: %s\n[!] driver_path: %s\n", g->application_path.c_str(), g->driver_path.c_str());

	*(uint64_t*)(driver_args.SpoofHash) = 0xAABBCCDDEEFFFFFF;
	*(uint64_t*)(driver_args.SpoofHash + 8) = 0xAABBCCDDEEFFFFFF;

	if (load_driver(&driver_args))
	{
		printf("[+] driver loaded\n");

		// resets & cleanups
		system("powershell Reset-PhysicalDisk *");
		system("net stop winmgmt /y");
		system("net start winmgmt /y");
		system("sc stop winmgmt");
		system("sc start winmgmt");

		Sleep(1000);
		deny_wmic();

		//// spoof registry
		//printf("[+] spoofing registry...\n");
		//spoof_registry();

		printf("[+] job done\n");
		Sleep( 3000 );
		return 0;
	}

	printf("[-] error: about to exit...\n");
	getchar();

	return -1;
}