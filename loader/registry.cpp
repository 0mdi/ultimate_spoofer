#include "registry.h"

#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <functional>
#include <string>

BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
{
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    TCHAR szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    // First, see if we can delete the key without having
    // to recurse.

    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS)
        return TRUE;

    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            //printf("Key not found.\n");
            return TRUE;
        }
        else {
            //printf("Error opening key.\n");
            return FALSE;
        }
    }

    // Check for an ending slash and add one if it is missing.

    lpEnd = lpSubKey + lstrlen(lpSubKey);

    if (*(lpEnd - 1) != TEXT('\\'))
    {
        *lpEnd = TEXT('\\');
        lpEnd++;
        *lpEnd = TEXT('\0');
    }

    // Enumerate the keys

    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS)
    {
        do {

            *lpEnd = TEXT('\0');
            StringCchCat(lpSubKey, MAX_PATH * 2, szName);

            if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
                break;
            }

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);

    // Try again to delete the key.

    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

//*************************************************************
//
//  RegDelnode()
//
//  Purpose:    Deletes a registry key and all its subkeys / values.
//
//  Parameters: hKeyRoot    -   Root key
//              lpSubKey    -   SubKey to delete
//
//  Return:     TRUE if successful.
//              FALSE if an error occurs.
//
//*************************************************************

BOOL RegDelnode(HKEY hKeyRoot, LPCTSTR lpSubKey)
{
    TCHAR szDelKey[MAX_PATH * 2];

    StringCchCopy(szDelKey, MAX_PATH * 2, lpSubKey);
    return RegDelnodeRecurse(hKeyRoot, szDelKey);

}

BOOL RegDelValue(HKEY hKeyRoot, LPCTSTR lpSubKey, LPCTSTR lpValueName)
{
    HKEY hKey = NULL;
    if (RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return FALSE;
    
    auto result = RegDeleteValue(hKey, lpValueName);
    RegCloseKey(hKey);

    return SUCCEEDED(result);
}

BOOL RandomizeGUIDStr(HKEY hKeyRoot, LPCTSTR lpSubKey, LPCTSTR lpValueName, bool lowercase=false, bool brackets=true)
{
    HKEY hKey = NULL;
    if (RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return FALSE;

    wchar_t char_table[17];
    wchar_t random_guid[50] = { 0 };
    wcscpy_s(random_guid, L"{XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}");
    wcscpy_s(char_table, L"0123456789ABCDEF");

    if (lowercase)
        wcscpy_s(char_table, L"0123456789abcdef");
    if (!brackets)
        wcscpy_s(random_guid, L"XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX");

    for (unsigned int i = 0; i < wcslen(random_guid); ++i)
    {
        if (random_guid[i] == L'X')
        {
            auto index = rand() % 16;
            random_guid[i] = char_table[index];
        }
    }

    printf("random_guid: %ws\n", random_guid);
    auto result = RegSetValue(hKey, lpValueName, REG_SZ, random_guid, (wcslen(random_guid) + 1) * 2);

    //auto result = RegDeleteValue(hKey, lpValueName);
    RegCloseKey(hKey);

    return SUCCEEDED(result);
}

wchar_t guids_cache[0x1000] = { 0 };
BOOL MutateGUIDStrs(HKEY hKeyRoot, LPCTSTR lpSubKey, LPCTSTR lpValueName, bool lowercase = false)
{
    HKEY hKey = NULL;
    if (RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return FALSE;

    wchar_t char_table[] = L"0123456789ABCDEF";
    if (lowercase)
        wcscpy_s(char_table, L"0123456789abcdef");
    
    memset(guids_cache, 0, sizeof(guids_cache));
    DWORD value_size = sizeof(guids_cache);
    auto result = RegGetValue(hKeyRoot, lpSubKey, lpValueName, RRF_RT_REG_SZ, 0, (PVOID)guids_cache, &value_size);
    if (!result && value_size > 0)
    {
        for (unsigned int i = 0; i < wcslen(guids_cache); ++i)
        {
            auto& c = guids_cache[i];

            if (c != L'.' && c != L'\\' && c != L'&' && c != L'\n')
            {
                auto rnd = rand() % wcslen(char_table) - 1;
                c = char_table[rnd];
            }
        }

        result = RegSetValue(hKey, lpValueName, REG_SZ, guids_cache, (wcslen(guids_cache) + 1) * 2);
    }

    //auto result = RegDeleteValue(hKey, lpValueName);
    RegCloseKey(hKey);

    return SUCCEEDED(result);
}

void MutateString(wchar_t* buf)
{
    wchar_t old_buf[150] = { 0 };
    wcscpy_s(old_buf, buf);

    for (unsigned int i = 0; i < wcslen(buf); ++i)
    {
        auto& c = buf[i];

        if (c != L'.' && c != L'\\' && c != L'&')
        {
            auto rnd = rand() % 3;
            if (rnd == 0)
                c -= 1;
            else if (rnd == 1)
                c += 1;
        }
    }

    printf("%s: %ws to %ws\n", __FUNCTION__, old_buf, buf);
}

BOOL RegMutateStr(HKEY hKeyRoot, LPCTSTR lpSubKey, LPCTSTR lpValueName)
{
    HKEY hKey = NULL;
    if (RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return FALSE;

    wchar_t value_buf[250] = { 0 };
    DWORD value_size = sizeof(value_buf);
    auto result = RegGetValue(hKeyRoot, lpSubKey, lpValueName, RRF_RT_REG_SZ, 0, (PVOID)value_buf, &value_size);
    if (result == 0)
    {
        MutateString(value_buf);
        result = RegSetValue(hKey, lpValueName, REG_SZ, value_buf, value_size);
    }

    //auto result = RegDeleteValue(hKey, lpValueName);
    RegCloseKey(hKey);

    return SUCCEEDED(result);
}

BOOL OnRegKeyStrExists(HKEY hKeyRoot, LPTSTR lpSubKey, LPCTSTR lpValueName, const std::function<void(wchar_t*)>& fn)
{
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    TCHAR szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_ALL_ACCESS, &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            //printf("Key not found.\n");
            return TRUE;
        }
        else {
            //printf("Error opening key.\n");
            return FALSE;
        }
    }

    // Check if lpValueName is present
    wchar_t value_buf[250] = { 0 };
    DWORD value_size = sizeof(value_buf);
    auto result = RegGetValue(hKeyRoot, lpSubKey, lpValueName, RRF_RT_REG_SZ, 0, (PVOID)value_buf, &value_size);
    if (!result && value_size > 0)
    {
        fn(value_buf);
        result = RegSetValueEx(hKey, lpValueName, 0, REG_SZ, (const BYTE*)value_buf, value_size);
    }

    // Check for an ending slash and add one if it is missing.

    lpEnd = lpSubKey + lstrlen(lpSubKey);
    if (*(lpEnd - 1) != TEXT('\\'))
    {
        *lpEnd = TEXT('\\');
        lpEnd++;
        *lpEnd = TEXT('\0');
    }

    // Enumerate the keys
    unsigned int cur_reg_index = 0;

    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, cur_reg_index++, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);


    if (lResult == ERROR_SUCCESS)
    {
        do {

            *lpEnd = TEXT('\0');
            StringCchCat(lpSubKey, MAX_PATH * 2, szName);

            OnRegKeyStrExists(hKeyRoot, lpSubKey, lpValueName, fn);


            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, cur_reg_index++, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);


    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

BOOL OnRegKeyBinExists(HKEY hKeyRoot, LPTSTR lpSubKey, LPCTSTR lpValueName, const std::function<void(unsigned char*, unsigned int)>& fn)
{
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    TCHAR szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_ALL_ACCESS, &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            //printf("Key not found.\n");
            return TRUE;
        }
        else {
            //printf("Error opening key.\n");
            return FALSE;
        }
    }

    // Check if lpValueName is present
    unsigned char value_buf[0x200] = { 0 };
    DWORD value_size = sizeof(value_buf);
    if (SUCCEEDED(RegQueryValueExW(hKey, lpValueName, 0, 0, value_buf, &value_size)))
    {
        fn(value_buf, value_size);
        auto result = RegSetValueEx(hKey, lpValueName, 0, REG_BINARY, value_buf, value_size);
    }

    // Check for an ending slash and add one if it is missing.

    lpEnd = lpSubKey + lstrlen(lpSubKey);

    if (*(lpEnd - 1) != TEXT('\\'))
    {
        *lpEnd = TEXT('\\');
        lpEnd++;
        *lpEnd = TEXT('\0');
    }

    // Enumerate the keys
    unsigned int cur_reg_index = 0;

    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, cur_reg_index++, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS)
    {
        do {

            *lpEnd = TEXT('\0');
            StringCchCat(lpSubKey, MAX_PATH * 2, szName);

            OnRegKeyBinExists(hKeyRoot, lpSubKey, lpValueName, fn);


            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, cur_reg_index++, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);


    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

BOOL DeleteRegKeysRec(HKEY hKeyRoot, LPTSTR lpSubKey, const std::vector<std::wstring>& keys_to_delete)
{
    printf("%ws\n", lpSubKey);

    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    TCHAR szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_ALL_ACCESS, &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        if (wcslen(lpSubKey) > 1)
        {
            if (lResult == ERROR_FILE_NOT_FOUND) {
                //printf("Key not found.\n");
                return TRUE;
            }
            else {
                //printf("Error opening key.\n");
                return FALSE;
            }
        }
        hKey = hKeyRoot;
    }

    // Check if lpSubKey is present
    for (auto& nvm : keys_to_delete)
    {
        auto wstr = std::wstring(lpSubKey);
        if (wstr.find(nvm) != std::wstring::npos)
        {
            RegDelnode(hKeyRoot, lpSubKey);
            break;
        }
    }

    // Check for an ending slash and add one if it is missing.

    lpEnd = lpSubKey + lstrlen(lpSubKey);

    if (lpEnd != lpSubKey)
    {
        if (*(lpEnd - 1) != TEXT('\\'))
        {
            *lpEnd = TEXT('\\');
            lpEnd++;
            *lpEnd = TEXT('\0');
        }
    }


    // Enumerate the keys
    unsigned int cur_reg_index = 0;

    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, cur_reg_index++, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS)
    {
        do {

            *lpEnd = TEXT('\0');
            StringCchCat(lpSubKey, MAX_PATH * 2, szName);

            DeleteRegKeysRec(hKeyRoot, lpSubKey, keys_to_delete);

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, cur_reg_index++, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);


    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

std::vector<std::wstring> GetSubKeys(HKEY hKeyRoot)
{
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    TCHAR szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    lResult = RegOpenKeyEx(hKeyRoot, nullptr, 0, KEY_ALL_ACCESS, &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            //printf("Key not found.\n");
            return {};
        }
        else {
            //printf("Error opening key.\n");
            return {};
        }
    }

    // Enumerate the keys
    unsigned int cur_reg_index = 0;

    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, cur_reg_index++, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    std::vector<std::wstring> result;
    if (lResult == ERROR_SUCCESS)
    {
        do {

            result.push_back(szName);


            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, cur_reg_index++, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }


    RegCloseKey(hKey);
    return result;
}

// Infinite Spoofer Ripped
wchar_t rec_buf[0x5000] = { 0 };
#define BUF(x) (wcscpy_s(rec_buf, x) ? rec_buf : rec_buf)
void spoof_registry()
{
    RegDelnode(HKEY_CURRENT_USER, L"Software\\Blizzard Entertainment");
    RegDelnode(HKEY_CURRENT_USER, L"Software\\Hex-Rays\\IDA\\History"); RegDelnode(HKEY_CURRENT_USER, L"Software\\Hex-Rays\\IDA\\History64");
    RegDelnode(HKEY_CURRENT_USER, L"Software\\Microsoft\\OneDrive\\Accounts");
    RegDelValue(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket", L"LastEnum");
    RegDelnode(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume");
    RegDelnode(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2");
    RegDelnode(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");

    for (uint8_t i = 0; i < 32; ++i)
    {
        wchar_t reg_key[150] = { 0 };
        wsprintf(reg_key, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%i", i);
        RandomizeGUIDStr(HKEY_LOCAL_MACHINE, reg_key, L"ServiceName");
    }

    RandomizeGUIDStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"UserModeDriverGUID");
    RegMutateStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"MatchingDeviceId");
    RegMutateStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"HardwareInformation.BiosString");
    RegMutateStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"DriverVersion");

    for (unsigned int i = 0; i < 32; ++i)
    {
        wchar_t reg_path[150] = { 0 };
        wsprintf(reg_path, L"SYSTEM\\ControlSet001\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\%04i", i);
        RegDelValue(HKEY_LOCAL_MACHINE, reg_path, L"InstallTimeStamp");
    }

    for (unsigned int i = 0; i < 8; ++i)
    {
        wchar_t reg_path[150] = { 0 };
        wsprintf(reg_path, L"SYSTEM\\ControlSet001\\Control\\IDConfigDB\\Hardware Profiles\\%04i", i);
        RandomizeGUIDStr(HKEY_LOCAL_MACHINE, reg_path, L"HwProfileGuid", true, true);
    }

    RandomizeGUIDStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\ProductOptions", L"OSProductContentId", true, false);
    RandomizeGUIDStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\SystemInformation", L"ComputerHardwareId", true, true);
    MutateGUIDStrs(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\SystemInformation", L"ComputerHardwareIds", true);


    MutateGUIDStrs(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\SystemInformation", L"ComputerHardwareIds", true);

    OnRegKeyStrExists(HKEY_LOCAL_MACHINE, BUF(L"SYSTEM\\ControlSet001\\Control\\Video"), L"DriverVersion", [&](wchar_t* buf)
        {
            MutateString(buf);
        });
    OnRegKeyStrExists(HKEY_LOCAL_MACHINE, BUF(L"SYSTEM\\ControlSet001\\Control\\Video"), L"HardwareInformation.BiosString", [&](wchar_t* buf)
        {
            MutateString(buf);
        });
    OnRegKeyStrExists(HKEY_LOCAL_MACHINE, BUF(L"SYSTEM\\ControlSet001\\Control\\Video"), L"MatchingDeviceId", [&](wchar_t* buf)
        {
            MutateString(buf);
        });
    OnRegKeyStrExists(HKEY_LOCAL_MACHINE, BUF(L"SYSTEM\\ControlSet001\\Control\\Video"), L"UserModeDriverGUID", [&](wchar_t* buf)
        {
            MutateString(buf);
        });

    OnRegKeyBinExists(HKEY_LOCAL_MACHINE, BUF(L"SYSTEM\\ControlSet001\\Enum\\DISPLAY"), L"EDID", [&](unsigned char* buf, unsigned int size)
        {
            for (size_t i = 0; i < size; i++)
                buf[i] = rand() % 256;
        });

    RegMutateStr(HKEY_LOCAL_MACHINE, (wchar_t*)L"SYSTEM\\ControlSet001\\Services\\monitor\\Enum", L"0");

    RegDelValue(HKEY_LOCAL_MACHINE, (wchar_t*)L"SYSTEM\\ControlSet001\\Services\\mssmbios", L"AcpiData");
    RegDelValue(HKEY_LOCAL_MACHINE, (wchar_t*)L"SYSTEM\\ControlSet001\\Services\\mssmbios", L"BiosData");
    RegDelValue(HKEY_LOCAL_MACHINE, (wchar_t*)L"SYSTEM\\ControlSet001\\Services\\mssmbios", L"RegistersData");
    RegDelValue(HKEY_LOCAL_MACHINE, (wchar_t*)L"SYSTEM\\ControlSet001\\Services\\mssmbios", L"SMBiosData");

    // Tcpip Parameters Adapters TODO
    // ...


    OnRegKeyBinExists(HKEY_LOCAL_MACHINE, BUF(L"SYSTEM\\ControlSet001\\Services\\Tcpip6\\Parameters"), L"Dhcpv6UID", [&](unsigned char* buf, unsigned int size)
        {
            for (size_t i = 0; i < size; i++)
                buf[i] = rand() % 256;
        });

    OnRegKeyBinExists(HKEY_LOCAL_MACHINE, BUF(L"SYSTEM\\ControlSet001\\Services\\TPM\\WMI"), L"WindowsAIKHash", [&](unsigned char* buf, unsigned int size)
        {
            for (size_t i = 0; i < size; i++)
                buf[i] = rand() % 256;
        });

    RandomizeGUIDStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"UserModeDriverGUID");
    RegMutateStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"MatchingDeviceId");
    RegMutateStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"HardwareInformation.BiosString");
    RegMutateStr(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"DriverVersion");

    for (unsigned int i = 0; i < 32; ++i)
    {
        wchar_t reg_path[150] = { 0 };
        wsprintf(reg_path, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\%04i", i);
        RegDelValue(HKEY_LOCAL_MACHINE, reg_path, L"InstallTimeStamp");
    }

    RegDelnode(HKEY_LOCAL_MACHINE, L"SYSTEM\\MountedDevices");

    // Delete all these keys from HKEY_USERS
    std::vector<std::wstring> to_delete;
    to_delete.push_back(L"Blizzard Entertainment");
    to_delete.push_back(L"IDA\\History");
    to_delete.push_back(L"BitBucket\\Volume");
    to_delete.push_back(L"Explorer\\MountPoints2");
    to_delete.push_back(L"Explorer\\UserAssist");

    auto sub_keys = GetSubKeys(HKEY_USERS);
    for (auto& sub : sub_keys)
    {     
        RegDelnode(HKEY_USERS, (sub + L"\\Software\\Blizzard Entertainment").c_str());
        RegDelnode(HKEY_USERS, (sub + L"\\Software\\Hex-Rays\\IDA\\History").c_str());
        RegDelnode(HKEY_USERS, (sub + L"\\Software\\Hex-Rays\\IDA\\History64").c_str());
        RegDelnode(HKEY_USERS, (sub + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume").c_str());
        RegDelnode(HKEY_USERS, (sub + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2").c_str());
        RegDelnode(HKEY_USERS, (sub + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist").c_str());
    }

}
   