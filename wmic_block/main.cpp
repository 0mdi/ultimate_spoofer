#include <Windows.h>
#include <AclAPI.h>
#include <AccCtrl.h>
#include <sddl.h>
#include <string>

#define skCrypt(x) x

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

DWORD AddAceToObjectsSecurityDescriptor(
    LPTSTR pszObjName,          // name of object
    SE_OBJECT_TYPE ObjectType,  // type of object
    LPTSTR pszTrustee,          // trustee for new ACE
    TRUSTEE_FORM TrusteeForm,   // format of trustee structure
    DWORD dwAccessRights,       // access mask for new ACE
    ACCESS_MODE AccessMode,     // type of ACE
    DWORD dwInheritance         // inheritance flags for new ACE
)
{
    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    if (NULL == pszObjName)
        return ERROR_INVALID_PARAMETER;

    // Get a pointer to the existing DACL.

    dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &pOldDACL, NULL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance = dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.ptstrName = pszTrustee;

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes) {
        goto Cleanup;
    }

    // Attach the new ACL as the object's DACL.

    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes) {
        goto Cleanup;
    }

Cleanup:

    if (pSD != NULL)
        LocalFree((HLOCAL)pSD);
    if (pNewDACL != NULL)
        LocalFree((HLOCAL)pNewDACL);

    return dwRes;
}

bool deny_connect_alpc(uint32_t pid, uint64_t alpc_handle)
{
    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hProcess)
    {
        //printf("OpenProcess failed: %i\n", GetLastError());
        return false;
    }

    HANDLE target_alpc_handle = NULL;
    if (!DuplicateHandle(hProcess, (HANDLE)alpc_handle, GetCurrentProcess(), &target_alpc_handle, 0, false, DUPLICATE_SAME_ACCESS))
    {
        //printf("DuplicateHandle failed: %i\n", GetLastError());
        return false;
    }

    SECURITY_ATTRIBUTES sa;
    auto szSD = TEXT("D:P");

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(szSD, SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL))
        return FALSE;

    if (!SetKernelObjectSecurity(target_alpc_handle, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor))
        return FALSE;

    CloseHandle(target_alpc_handle);

    return TRUE;
}

PVOID GetLibraryProcAddress(const char* LibraryName, const char* ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

bool get_process_alpc_port_handle(uint32_t pid, HANDLE& alpc_handle)
{
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
        GetLibraryProcAddress(skCrypt("ntdll.dll"), skCrypt("NtQuerySystemInformation"));
    _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)
        GetLibraryProcAddress(skCrypt("ntdll.dll"), skCrypt("NtDuplicateObject"));
    _NtQueryObject NtQueryObject = (_NtQueryObject)
        GetLibraryProcAddress(skCrypt("ntdll.dll"), skCrypt("NtQueryObject"));
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle;
    ULONG i;


    if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
    {
        //printf("Could not open PID %d! (Don't try to open a system process.)\n", pid);
        return false;
    }

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    /* NtQuerySystemInformation won't give us the correct buffer size,
       so we guess by doubling the buffer size. */
    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    /* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
    if (!NT_SUCCESS(status))
    {
        //printf("NtQuerySystemInformation failed!\n");
        return false;
    }

    for (i = 0; i < handleInfo->HandleCount; i++)
    {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;

        /* Check if this handle belongs to the PID the user specified. */
        if (handle.ProcessId != pid)
            continue;

        /* Duplicate the handle so we can query it. */
        if (!NT_SUCCESS(NtDuplicateObject(
            processHandle,
            (HANDLE)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            0
        )))
        {
            //printf("[%#x] Error!\n", handle.Handle);
            continue;
        }

        /* Query the object type. */
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
        )))
        {
            //printf("[%#x] Error!\n", handle.Handle);
            CloseHandle(dupHandle);
            continue;
        }

        /* Query the object name (unless it has an access of
           0x0012019f, on which NtQueryObject could hang. */
        if (handle.GrantedAccess == 0x0012019f)
        {
            /* We have the type, so display that. */
            //printf(
            //    "[%#x] %.*S: (did not get name)\n",
            //    handle.Handle,
            //    objectTypeInfo->Name.Length / 2,
            //    objectTypeInfo->Name.Buffer
            //);
            free(objectTypeInfo);
            CloseHandle(dupHandle);
            continue;
        }

        objectNameInfo = malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength
        )))
        {
            /* Reallocate the buffer and try again. */
            objectNameInfo = realloc(objectNameInfo, returnLength);
            if (!NT_SUCCESS(NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
            )))
            {
                /* We have the type name, so just display that. */
                //printf(
                //    "[%#x] %.*S: (could not get name)\n",
                //    handle.Handle,
                //    objectTypeInfo->Name.Length / 2,
                //    objectTypeInfo->Name.Buffer
                //);
                free(objectTypeInfo);
                free(objectNameInfo);
                CloseHandle(dupHandle);
                continue;
            }
        }

        /* Cast our buffer into an UNICODE_STRING. */
        objectName = *(PUNICODE_STRING)objectNameInfo;

        /* Print the information! */
        if (objectName.Length)
        {
            /* The object has a name. */
            printf(
                "[%#x] %.*S: %.*S\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer,
                objectName.Length / 2,
                objectName.Buffer
            );

            if (std::wstring(objectTypeInfo->Name.Buffer).find(skCrypt(L"ALPC Port")) != std::wstring::npos &&
                std::wstring(objectName.Buffer).find(skCrypt(L"RPC Control")) != std::wstring::npos)
            {
                alpc_handle = (HANDLE)handle.Handle;
            }
        }
        else
        {
            /* Print something else. */
            printf(
                "[%#x] %.*S: (unnamed)\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer
            );
        }

        free(objectTypeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);

        if (alpc_handle != NULL)
            break;
    }

    free(handleInfo);
    CloseHandle(processHandle);
    return alpc_handle != NULL;
}

BOOL RegReadDword(HKEY hKeyRoot, LPCTSTR lpSubKey, LPCTSTR lpValueName, DWORD& value)
{
    HKEY hKey = NULL;
    if (RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return FALSE;

    DWORD value_size = sizeof(value);
    auto result = RegGetValue(hKeyRoot, lpSubKey, lpValueName, REG_DWORD, 0, (PVOID)&value, &value_size);
    RegCloseKey(hKey);

    return SUCCEEDED(result);
}

bool deny_wmic()
{
    // before enabling or disabling we want to refresh the registry by executing a wbem query
    system(skCrypt("wmic diskdrive get serialnumber,model"));

    // read pid from registry
    DWORD alpc_pid = 0;
    if (!RegReadDword(HKEY_LOCAL_MACHINE, skCrypt(L"SOFTWARE\\Microsoft\\Wbem\\Transports\\Decoupled\\Server"), skCrypt(L"ProcessIdentifier"), alpc_pid))
    {
        return false;
    }

    HANDLE alpc_handle = NULL;
    if (!get_process_alpc_port_handle(alpc_pid, alpc_handle))
    {
        return false;
    }

    return deny_connect_alpc(alpc_pid, (uint64_t)alpc_handle);
}

int main(int argc, char** argv)
{
    printf("wmic blocker by omdi\n");

    getchar();

    if (deny_wmic())
        printf("success\n");
    else
        printf("error\n");

    getchar();
	return 0;
}