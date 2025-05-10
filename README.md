This repository hosts a Hardware ID (HWID) spoofer toolkit, originally developed in 2021, which has remained effective and undetected. Its creation drew upon various online resources and communities, including UnKnoWnCheaTs, insights from 'btbd' (many thanks!), the ReactOS project and parts of ProcessHacker.

**Components:**

* **`driver`**:
    * The core component detailed in the technical writeup below. It implements kernel-mode bypassing techniques and bootstraps the kernel shellcode.
* **`driver_shellcode`**:
    * Contains the main spoofing logic. All functions are force-inlined and segmented to simplify shellcode extraction, contributing to its structural complexity.
* **`loader`**:
    * Prepares the driver for loading and performs cleanup operations.
    * *Note: Functionality for dynamically obtaining PDB offsets has been removed. Users will need to reimplement this or provide necessary offsets manually.*
* **`scripts`**:
    * A collection of helper scripts, including tools for shellcode extraction and other development tasks.
* **`spoof_checker`**:
    * A utility to retrieve various hardware serial numbers, useful for verifying the spoofer's effectiveness.
* **`wmic_block`**:
    * A standalone user-mode application designed to disrupt or block Windows Management Instrumentation (WMI/WMIC) queries.
---

## Technical Writeup: Stealthy Hardware ID Spoofing via Windows Kernel Manipulation

This documentation outlines advanced techniques for achieving stealthy hardware ID spoofing by targeting specific Windows kernel components and related system services. The methods discussed focus on disk serial numbers, Network Interface Card (NIC) MAC addresses, and disrupting Windows Management Instrumentation (WMI) queries.

### 1. Disk Serial Number Spoofing

Effective disk serial number spoofing requires intercepting I/O Request Packet (IRP) handlers for storage drivers, such as `stornvme.sys` (for NVMe drives) or `storahci.sys` (for AHCI SATA drives). A naive approach of directly replacing these handler addresses in the driver's dispatch table is often detected by system integrity checkers or fingerprinting solutions. These solutions typically verify that IRP handler pointers reside within the memory bounds of their legitimate parent driver and may perform code integrity checks on the driver's executable sections.

**1.1. IRP Handling Path and Target Selection**

On Windows, requests for disk serial numbers (e.g., via `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceProperty` or `StorageAdapterProperty`) can be routed through `disk.sys`. This driver then relays the request to the appropriate storport miniport driver (e.g., `stornvme.sys` or `storahci.sys`), which in turn communicates with `storport.sys` (the system port driver for storage devices).

```
Request Path: User Application -> disk.sys -> [stornvme.sys | storahci.sys] -> storport.sys -> Hardware
```

Fingerprinting solutions can bypass hooks on `disk.sys` by sending requests directly to the specific storport miniport driver. Therefore, a more robust approach targets these miniport drivers or the underlying `storport.sys`.

An interesting observation is that the IRP handlers for many storport miniport drivers (like `stornvme.sys` and `storahci.sys`) do not reside within their own driver's memory image. Instead, they often point to functions within `storport.sys`. This characteristic is crucial, as it presents an opportunity for stealthier redirection.

**1.2. Leveraging `storport.sys` Shims for Stealthy Hooks**

Instead of injecting custom code directly into the executable sections of a driver (which would fail integrity checks), this technique leverages existing, legitimate code sequences within `storport.sys`. Analysis of `storport.sys` reveals the use of the Kernel Shim Engine (KSE) through imports like `ntoskrnl!KseRegisterShim`. Shims are a mechanism used by Microsoft to apply targeted compatibility fixes to drivers. `storport.sys` registers several shims, for example:

```c
KseRegisterShim(&SrbShim, 0i64, 0i64);
KseRegisterShim(&DeviceIdShim, 0i64, 0i64);
KseRegisterShim(&ATADeviceIdShim, 0i64, 0i64);
```

Each shim has an associated hook function. Consider `SrbShimHookDeviceControl`:

```c
__int64 __fastcall SrbShimHookDeviceControl(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  // ... (initial setup and conditional fix logic) ...
  // v4 = SRB, v5 = IRP, v6 = DeviceObject, v7 = MajorFunction
  // ...
  // If a specific condition is met (e.g., IOCTL_STORAGE_QUERY_PROPERTY for adapter)
  // a completion routine might be set:
  // (*(void (__fastcall **)(__int64, __int64, __int64 (__fastcall *)(), _QWORD))(qword_1C007A118 + 8))(
  //                                v6, v5, SrbShimStorageAdapterPropertyCompletionHook, 0i64);
  // ...

  // Crucial part for redirection:
  v9 = (*(__int64 (__fastcall **)(_QWORD, __int64, __int64, __int64))qword_1C007A118)(*(_QWORD *)(v6 + 8), a2, v4, a4);
  return (*(__int64 (__fastcall **)(__int64, __int64, __int64, __int64))(v9 + 8 * v7 + 32))(v6, v5, v10, v11); // v10, v11 are params for original handler
}
```
The key observation is that `qword_1C007A118` is a function pointer located in the `.data` section of `storport.sys`, which is typically writable. By overwriting this pointer to direct to custom shellcode, we can gain control. This shellcode's responsibility is to return a crafted `v9` value (a pointer to a structure or dispatch table). The subsequent call, `(*(v9 + 8 * v7 + 32))`, will then use this controlled `v9` to call an arbitrary function with the original arguments desired for spoofing (DeviceObject, IRP, etc.).

The IRP handler of the target storport miniport driver can then be replaced with the address of `storport!SrbShimHookDeviceControl` (or `ATADeviceIdShimHookDeviceControl`, etc.). This passes bounds checks, as the handler points within `storport.sys`. Since no `.text` section is patched, code integrity checks are also satisfied. Similar structures exist for `ATADeviceIdShimHookDeviceControl` and another shim, providing multiple potential hooks.

```c
// Example snippet from ATADeviceIdShimHookDeviceControl
// ...
v11 = (*(__int64 (__fastcall **)(_QWORD, __int64, unsigned __int8 *, __int64))qword_1C007A308)(
        *(_QWORD *)(v7 + 8), // Lower Device Object
        a2,                  // IRP
        v6,                  // SRB
        a4);                 // Context
return (*(__int64 (__fastcall **)(__int64, __int64, __int64, __int64))(v11 + 8 * v8 + 32))(v7, v5, v12, v13); // v8 = MajorFunction
```
Here, `qword_1C007A308` is another writable function pointer in `.data`.

**1.3. Disabling Active Shims**

Directly hijacking these shim-related functions while the shims are actively registered and managed by the KSE can lead to system instability (Blue Screen of Death - BSOD). To prevent this, the relevant shims must be unregistered from the KSE before their handler invocation mechanisms are repurposed. This involves:
1.  Locating the internal KSE registration structure for the shim.
2.  Modifying a status field within this structure using Direct Kernel Object Manipulation (DKOM) to mark the shim as suitable for unregistration (e.g., `*(uint32_t*)(dkom_struct + 0x18) = 0;`).
3.  Calling the exported `ntoskrnl!KseUnregisterShim` function.

The following code illustrates this process:
```c
// KseEngine is a global pointer to KSE's main structure in ntoskrnl.
// Shim is a pointer to the shim structure (e.g., SrbShim in storport.sys).

uint64_t __fastcall KsepIsShimRegistered(uint64_t KseEngineAddr, uint64_t* ShimDeref0x8, uint64_t unused, uint64_t* outInternalStruct)
{
    // ... (Logic to find the internal shim registration structure by iterating KSE's list)
    // This function verifies if a shim is registered and retrieves its internal KSE structure.
    // (Original code from writeup)
    unsigned int v4; // er8
    uint64_t* outInternalStruct_1; // r11
    uint64_t* ShimDeref0x8_1; // rbx
    uint64_t KseEnginePlus0x10; // r10
    uint64_t* KseEngineDeref0x10; // rcx
    uint64_t v9; // r9
    uint64_t* v10; // rdi
    uint64_t v11; // rdx

    v4 = 0;
    outInternalStruct_1 = outInternalStruct;
    ShimDeref0x8_1 = ShimDeref0x8;
    if (!ShimDeref0x8 || !KseEngineAddr)
        return 0i64;
    KseEnginePlus0x10 = KseEngineAddr + 0x10;
    KseEngineDeref0x10 = *(uint64_t**)(KseEngineAddr + 0x10);
    while (KseEngineDeref0x10 != (uint64_t*)KseEnginePlus0x10)
    {
        v9 = (uint64_t)KseEngineDeref0x10;
        KseEngineDeref0x10 = (uint64_t*)*KseEngineDeref0x10;
        if (!(*(uint32_t*)(v9 + 0x1C) & 4)) // Check flags
        {
            v10 = *(uint64_t**)(*(uint64_t*)(v9 + 16) + 8i64); // Dereference to get to shim identifiers
            v11 = *v10 - *ShimDeref0x8_1;
            if (*v10 == *ShimDeref0x8_1)
                v11 = v10[1] - ShimDeref0x8_1[1]; // Compare both parts of the shim identifier
            if (!v11)
            {
                if (outInternalStruct_1)
                    *outInternalStruct_1 = v9; // Return the internal KSE structure for this shim
                return 1; // Found
            }
        }
    }
    return v4; // Not found
}

DRIVER_STATUS ForceUnregisterShim(uint64_t ShimIdentifierStructAddress) // ShimIdentifierStructAddress is like &SrbShim from storport
{
    uint64_t internal_kse_struct = 0;
    // KseEngine needs to be resolved (e.g. ntoskrnl.base + KseEngine_offset)
    // The second argument to KsepIsShimRegistered is a pointer to the shim's unique ID, often at ShimIdentifierStructAddress + 0x8.
    if (!KsepIsShimRegistered(KseEngine, *(uint64_t**)(ShimIdentifierStructAddress + 0x8), 0, &internal_kse_struct) || !internal_kse_struct)
    {
        LOG("KsepIsShimRegistered failed for shim structure at %llx", ShimIdentifierStructAddress);
        return KSE_INTERNAL_STRUCT_NOT_FOUND; // Custom error
    }

    LOG("Internal KSE struct for shim: %llx, Flags field (+0x18): %x", internal_kse_struct, *(uint32_t*)(internal_kse_struct + 0x18));

    // DKOM: Modify flags that might prevent unregistration.
    // The specific offset 0x18 (or 0x1C based on KsepIsShimRegistered logic) relates to flags.
    // Assuming dkom_struct + 0x18 holds state/flags preventing unregistration.
    // The original code uses (dkom_struct + 0x18), KsepIsShimRegistered checks (v9 + 0x1C). This needs to be consistent.
    // For demonstration, using the original's reference:
    *(uint32_t*)(internal_kse_struct + 0x18) = 0; // Neutralize flags preventing unregistration

    NTSTATUS status;
    // KseUnregisterShim takes the main shim structure address (e.g., &SrbShim)
    CALL_RET(status, KseUnregisterShim, (PVOID)ShimIdentifierStructAddress);
    if (!NT_SUCCESS(status))
    {
        LOG("KseUnregisterShim failed with status %x for shim structure at %llx", status, ShimIdentifierStructAddress);
        return SHIM_UNREGISTER_FAILED;
    }

    LOG("Successfully unregistered shim via KSE for shim structure at %llx", ShimIdentifierStructAddress);
    return SUCCESS;
}

DRIVER_STATUS DismantleKseShims() // Renamed for clarity
{
    // ... (Resolve storport.sys base, ntoskrnl.exe base, and offsets for SrbShim, DeviceIdShim, ATADeviceIdShim, KseEngine)
    // ... (Error handling for not found components)

    // Example:
    // SrbShimAddr = storport.base + g.args.SrbShim;
    // DeviceIdShimAddr = storport.base + g.args.DeviceIdShim;
    // ATADeviceIdShimAddr = storport.base + g.args.ATADeviceIdShim;
    // KseEngine = ntoskrnl.base + KseEngine_offset;

    if (ForceUnregisterShim(SrbShimAddr) != SUCCESS ||
        ForceUnregisterShim(DeviceIdShimAddr) != SUCCESS ||
        ForceUnregisterShim(ATADeviceIdShimAddr) != SUCCESS)
    {
        return KSE_UNREGISTER_FAILED;
    }

    LOG("All targeted shims unregistered successfully!");
    return SUCCESS;
}
```

**1.4. Identifying Target Storage Drivers**

To determine which storage miniport drivers are active and require hooking, their names can be retrieved from the Windows Registry:
```c
wchar_t scsi_drivers[MAX_SCSI_DRIVERS][DRIVER_NAME_MAX_LEN] = {0}; // Define appropriate constants
int scsi_driver_count = 0;

DRIVER_STATUS CacheScsiDriverName(int scsi_port_index)
{
    if (scsi_driver_count >= MAX_SCSI_DRIVERS)
        return DRIVER_LIMIT_REACHED; // Custom error

    wchar_t registry_path[128];
    NTSTATUS status = RtlStringCchPrintfW(registry_path, sizeof(registry_path)/sizeof(wchar_t),
                                L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d", scsi_port_index);
    if (!NT_SUCCESS(status))
        return REGISTRY_PATH_CONSTRUCTION_FAILED;

    UNICODE_STRING driver_value_unicode;
    RtlInitUnicodeString(&driver_value_unicode, NULL); // Important to initialize

    // GetRegistryStrValue is a custom helper function to read a REG_SZ value.
    if (NT_SUCCESS(GetRegistryStrValue(registry_path, L"Driver", &driver_value_unicode)) && driver_value_unicode.Buffer)
    {
        // Ensure buffer is large enough and null-terminated.
        wcsncpy(scsi_drivers[scsi_driver_count], driver_value_unicode.Buffer, DRIVER_NAME_MAX_LEN - 1);
        scsi_drivers[scsi_driver_count][DRIVER_NAME_MAX_LEN - 1] = L'\0'; // Ensure null termination

        LOG("Found SCSI driver via registry: %ws for Scsi Port %d", scsi_drivers[scsi_driver_count], scsi_port_index);
        scsi_driver_count++;
        ExFreePool(driver_value_unicode.Buffer); // If GetRegistryStrValue allocates memory
        return SUCCESS;
    }
    return DRIVER_REGISTRY_VALUE_NOT_FOUND;
}
```
This allows targeted hooking of only the necessary drivers. Note that comprehensive disk spoofing also involves modifying other data structures and responses beyond just the serial number from `IOCTL_STORAGE_QUERY_PROPERTY`. Details for such modifications are extensive and depend on the specific data being targeted (check driver/disk.cpp).

### 2. NIC MAC Address Spoofing

Spoofing MAC addresses involves targeting the Network Driver Interface Specification (NDIS) wrapper library, `NDIS.sys`, and related network drivers. Similar to disk drivers, IRP handlers in `NDIS.sys` are potential targets.

**2.1. Potential Hook: `ndisDummyIrpHandler`**

Analysis of `NDIS.sys` reveals functions like `ndisDummyIrpHandler`.
```c
__int64 __fastcall ndisDummyIrpHandler(struct _DEVICE_OBJECT *a1, struct _IRP *a2)
{
  _BYTE *deviceExtension; // rbx
  struct _IRP *irp; // rdi
  struct _DEVICE_OBJECT *deviceObject; // rsi
  _IO_STACK_LOCATION *ioStackLocation; // rcx
  unsigned int status; // ebx
  __int64 (__fastcall *originalHandler)(struct _DEVICE_OBJECT *, struct _IRP *); // rax

  deviceExtension = deviceObject->DeviceExtension;
  irp = a2;
  deviceObject = a1;
  ioStackLocation = irp->Tail.Overlay.CurrentStackLocation;

  if ( *deviceExtension == 17 ) // Check a type field in DeviceExtension
  {
    status = (ioStackLocation->MajorFunction != IRP_MJ_PNP) ? 0xC00000BB : 0; // STATUS_NOT_SUPPORTED or STATUS_SUCCESS
LABEL_5:
    irp->IoStatus.Status = status;
    IofCompleteRequest(irp, IO_NO_INCREMENT);
    goto LABEL_6;
  }

  if ( *deviceExtension != 9 // Another type check
    || (originalHandler = *(__int64 (__fastcall **)(struct _DEVICE_OBJECT *, struct _IRP *))&deviceExtension[8
                                     + sizeof(PVOID) * (unsigned __int8)ioStackLocation->MajorFunction // Array of function pointers
                                     + 48]) == NULL ) // Offset to the array within DeviceExtension
  {
    status = 0xC00000BB; // STATUS_NOT_SUPPORTED
    goto LABEL_5;
  }
  status = originalHandler(deviceObject, irp); // Call the resolved handler
LABEL_6:
  return status;
}
```
This function's behavior is heavily dependent on the contents of the `DeviceExtension` of the `DEVICE_OBJECT`. If `*deviceExtension == 9`, it retrieves a function pointer `originalHandler` from an array within the `DeviceExtension` (e.g., `deviceExtension + 48 + MajorFunctionCode * sizeof(PVOID)`). By carefully modifying the `DeviceExtension` of target network device objects, it's possible to redirect this `originalHandler` to custom code. This requires enumerating network devices and patching their `DeviceExtension` accordingly.

**2.2. Alternative Hook: `KWorkItemBase::CallbackThunk` in NDIS**

A potentially more subtle technique involves a `CallbackThunk` function, such as one found within `KWorkItem<Ndis::BindEngine>` context:
```c
__int64 __fastcall KWorkItemBase_Ndis_BindEngine_KWorkItem_Ndis_BindEngine__CallbackThunk(__int64 workItemContext, __int64 contextParam)
{
  // workItemContext (a1) is a pointer to a structure.
  // The function pointer is at an offset (e.g., +40) from workItemContext.
  // The first argument to the called function is at another offset (e.g., +32).
  return (*(__int64 (__fastcall **)(_QWORD, __int64))(workItemContext + 40))(*(_QWORD *)(workItemContext + 32), contextParam);
}
```
If `workItemContext + 40` can be made to point to custom code, and this thunk is used by NDIS for IRP processing or related operations (e.g., via a work item callback that is part of the I/O path for MAC address queries like `OID_802_3_PERMANENT_ADDRESS`), this offers a redirection point. `workItemContext + 40` could correspond to `device->Timer` if this callback is associated with a device object's timer mechanism or a similar structure field.

The technique would involve:
1.  Enumerating network filter modules or device objects using structures like `PNDIS_FILTER_BLOCK`.
2.  Identifying the relevant device object or associated NDIS structure.
3.  Patching the field corresponding to `workItemContext + 40` (e.g., `device->Timer` or a similar callback pointer in an NDIS-specific structure) to point to the spoofing shellcode.
4.  Potentially swapping IRP handlers of the network device to use this `CallbackThunk` if it's not already in the path, or ensuring the conditions are met for this thunk to be called.

Empirical testing revealed that such modifications can be unstable. For instance, a BSOD during shutdown was mitigated by an additional patch:
```c
// Assuming 'device' is the DEVICE_OBJECT for the NIC
device->Timer = (PIO_TIMER)NICControl_shell; // NICControl_shell is the custom hook.
                                             // This assumes device->Timer aligns with workItemContext + 40.
*(uint8_t*)device->DeviceExtension = 0x12;   // Additional patch to a field in DeviceExtension for stability.
```

### 3. WMIC Query Disruption

Windows Management Instrumentation (WMI) is a common interface for querying system information, including various hardware identifiers (disk serials, MAC addresses, BIOS serials, CPU IDs).

```powershell
wmic diskdrive get serialnumber
wmic nic where PhysicalAdapter=True get MacAddress, Name
wmic bios get serialnumber
wmic cpu get ProcessorId
```

Even if underlying hardware queries are hooked as described above, WMI provides a higher-level abstraction that might bypass some hooks or retrieve cached/alternative data.

**3.1. Kernel-Mode WMI Tampering (Partial Success)**

An initial approach involved targeting WMI components within `ntoskrnl.exe`. The function `WmipDoFindRegEntryByProviderId` is involved in WMI provider registration lookups:
```c
void **__fastcall WmipDoFindRegEntryByProviderId(int providerIdToFind)
{
  void **currentEntry; // rax

  currentEntry = (void **)WmipInUseRegEntryHead; // Head of a linked list of registered providers
  if ( WmipInUseRegEntryHead == &WmipInUseRegEntryHead ) // List is empty or sentinel check
    return NULL;
  while ( *((_DWORD *)currentEntry + 14) != providerIdToFind || *((_DWORD *)currentEntry + 12) < 0 ) // Check ID and status flags
  {
    currentEntry = (void **)*currentEntry; // Next entry
    if ( currentEntry == &WmipInUseRegEntryHead ) // Reached end of list
      return NULL;
  }
  return currentEntry; // Found
}
```
Attempting to break this by setting `WmipInUseRegEntryHead = &WmipInUseRegEntryHead` (effectively making the list appear empty) partially crippled some WMIC commands but was not a comprehensive solution.

**3.2. User-Mode ALPC Port Access Denial (Effective Disruption)**

A more effective method involves targeting the user-mode WMI service. WMIC communicates with a WMI provider service, typically hosted in a `svchost.exe` instance, via Advanced Local Procedure Call (ALPC) / Remote Procedure Call (RPC). It's possible to disrupt this communication channel without kernel code execution by modifying the security permissions of the ALPC port used by the WMI service.

The steps are:
1.  **Refresh WMI Data (Optional but Recommended):** Execute a benign WMI query to ensure the service is active and its registry entries are populated.
    ```batch
    wmic diskdrive get serialnumber,model
    ```
2.  **Identify WMI Service PID:** The Process ID (PID) of the `svchost.exe` instance hosting the WMI core provider can often be found in the registry:
    `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Server\ProcessIdentifier`
3.  **Obtain ALPC Port Handle:** Enumerate handles within the identified WMI service process to find the relevant ALPC port handle. This requires a function like `get_process_alpc_port_handle(pid, &alpc_handle)` (implementation not shown, but typically involves `NtQuerySystemInformation` with `SystemHandleInformation`).
4.  **Modify ALPC Port Security:**
    * Duplicate the ALPC port handle from the target WMI service process into the current process using `DuplicateHandle`.
    * Create a security descriptor that denies all access (e.g., `D:P` - Deny Everyone All Access).
    * Apply this security descriptor to the duplicated ALPC port handle using `SetKernelObjectSecurity` with `DACL_SECURITY_INFORMATION`.

```c
bool deny_wmic_access() // Renamed for clarity
{
    // Optional: refresh WMI service state
    system(skCrypt("wmic diskdrive get serialnumber,model")); // skCrypt is a placeholder for string encryption

    DWORD wmi_service_pid = 0;
    if (!RegReadDword(HKEY_LOCAL_MACHINE, skCrypt(L"SOFTWARE\\Microsoft\\Wbem\\Transports\\Decoupled\\Server"), skCrypt(L"ProcessIdentifier"), wmi_service_pid))
    {
        LOG("Failed to read WMI service PID from registry.");
        return false;
    }

    HANDLE hAlpcPortInWmiProcess = NULL;
    // get_process_alpc_port_handle is a custom function to find the ALPC port handle
    // within the wmi_service_pid process that is used for WMI communications.
    if (!get_process_alpc_port_handle(wmi_service_pid, hAlpcPortInWmiProcess))
    {
        LOG("Failed to get ALPC port handle from WMI service PID: %u", wmi_service_pid);
        return false;
    }

    return deny_alpc_port_connections(wmi_service_pid, (uint64_t)hAlpcPortInWmiProcess);
}

bool deny_alpc_port_connections(uint32_t target_pid, uint64_t original_alpc_handle_value)
{
    HANDLE hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, target_pid);
    if (!hTargetProcess)
    {
        LOG("OpenProcess failed for PID %u: %u", target_pid, GetLastError());
        return false;
    }

    HANDLE hDuplicatedAlpcPort = NULL;
    if (!DuplicateHandle(hTargetProcess, (HANDLE)original_alpc_handle_value, GetCurrentProcess(), &hDuplicatedAlpcPort, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        LOG("DuplicateHandle failed: %u", GetLastError());
        CloseHandle(hTargetProcess);
        return false;
    }
    CloseHandle(hTargetProcess); // Close process handle once duplication is done

    SECURITY_ATTRIBUTES sa;
    // "D:P" is an SDDL string: (D;) Deny ACE type, (P) Principal Self (effectively denies Everyone due to empty SID) - Should be "D:(A;;GA;;;WD)" for Deny All to Everyone or similar.
    // A more explicit "Deny All to Everyone" SDDL string is "D:(A;;GA;;;WD)" or "D:P(D;OICI;GA;;;WD)"
    // Using "D:P" as per original, but it's unusual. A typical "Deny All" is "D:(D;OICI;GA;;;WD)" (Deny; ObjectInherit,ContainerInherit; GenericAll;;;Everyone)
    // For simplicity and to match original intent of maximum denial:
    LPWSTR sddl_string = TEXT("D:(A;;0x00000000;;;WD)"); // Deny NO ACCESS to Everyone (WD) - effectively denying any new connections.
                                                      // Or more strongly: D:(D;OICI;GA;;;WD) to deny Generic All.
                                                      // The original "D:P" might be intended to deny access to the owner/primary group.
                                                      // Let's use a clear Deny All for Everyone.
    sddl_string = TEXT("D:(A;;GA;;;WD)"); // Deny Generic All to World (Everyone)

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl_string, SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL))
    {
        LOG("ConvertStringSecurityDescriptorToSecurityDescriptor failed: %u", GetLastError());
        CloseHandle(hDuplicatedAlpcPort);
        return false;
    }

    if (!SetKernelObjectSecurity(hDuplicatedAlpcPort, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor))
    {
        LOG("SetKernelObjectSecurity failed: %u", GetLastError());
        LocalFree(sa.lpSecurityDescriptor); // Free the security descriptor memory
        CloseHandle(hDuplicatedAlpcPort);
        return false;
    }

    LocalFree(sa.lpSecurityDescriptor);
    CloseHandle(hDuplicatedAlpcPort);
    LOG("Successfully modified ALPC port security for PID %u, handle value %llx.", target_pid, original_alpc_handle_value);
    return TRUE;
}
```
After this modification, most WMIC commands will fail with an "Access Denied" error or similar, effectively disrupting WMI-based fingerprinting. However, this forceful approach might interfere with legitimate software installers or system components that rely on WMI, potentially causing them to hang or break.

---

### 4. Additional Evasion and Hardening Measures

While the previously described techniques aim to bypass common detection vectors such as driver memory bounds checks and code integrity verification of `.text` sections, the execution of custom (unsigned) code in the kernel still presents risks. Advanced fingerprinting solutions and security platforms (e.g., Endpoint Detection and Response systems with kernel agents, or hypervisor-enforced code integrity mechanisms) may employ methods to detect anomalous code execution. These can include:

* **Integrity Checks via Interrupts:** Utilizing Non-Maskable Interrupts (NMIs) or Asynchronous Procedure Calls (APCs) to periodically inspect system state, call stacks, or memory page permissions, potentially identifying deviations caused by unsigned code. For instance, APCs might be used to inject checking routines into various threads, and unusual execution within a data page or a non-backed executable page could be flagged.

To further complicate detection and enhance the resilience of these spoofing techniques, several additional measures are implemented:

**4.1. Granular and Dispersed Memory Allocation for Payloads**

Instead of allocating a single, contiguous block of memory for all hook handlers, completion routines, and other operational shellcode, a more granular approach is adopted. Each piece of custom code (referred to collectively as "driver shellcode," as it's often developed within a driver project before extraction) is allocated its own small segment of non-paged system memory.

This strategy offers several advantages:
* **Reduced Signature Surface:** Dispersed, smaller allocations are less likely to match signatures looking for large, monolithic blocks of suspicious executable code.
* **Mimicking Benign Allocations:** Small, isolated allocations can better blend in with legitimate system and driver memory usage patterns.

The shellcode itself is designed to be position-independent or easily relocatable to function correctly from these dynamically allocated memory regions.

**4.2. Targeted Code Obfuscation with LLVM**

To hinder static analysis and signature-based detection of the kernel shellcode, a targeted obfuscation strategy using LLVM-based tools (specifically `ollvm` integrated with `clang-cl` for Windows kernel driver compilation) is employed. To avoid significantly increasing the shellcode size, the focus is primarily on **light instruction substitution**. This technique replaces standard instructions with more complex, yet semantically equivalent, sequences of instructions, subtly altering the code's appearance at the machine level.

Even this relatively light form of obfuscation, when combined with the extensive use of hardcoded constants, proves highly effective. It ensures each compiled shellcode instance is sufficiently unique, thereby significantly impeding identification through common checksums or hash-based signature matching. The randomization inherent in this process further guarantees that signatures derived from one instance are unlikely to match others.

**4.3. Leveraging Hardcoded Constants with Obfuscation**

The kernel shellcode intentionally utilizes numerous hardcoded constants for critical values (e.g., offsets, specific IOCTL codes, magic numbers, or xor keys). When combined with the instruction substitution provided by `ollvm`, this approach becomes particularly powerful against hash-based or simple pattern-matching identification:

* While the constants themselves might be static within a given build, the obfuscation applied to the surrounding code alters how these constants are loaded, manipulated, and used. This makes it difficult to identify their purpose or to build reliable signatures based on their usage patterns alone.
* The randomization provided by `ollvm` ensures that the code structure surrounding these constants differs significantly between compilations, further complicating fingerprinting efforts.

**4.4. Force Inlining for Shellcode Modularity and Obfuscation Synergy**

To streamline the development and deployment of the kernel shellcode, all internal functions within the shellcode modules are aggressively force-inlined (`__forceinline` or equivalent compiler directives). This practice collapses distinct C functions into a single, monolithic block of machine code for each specific hook handler or routine.

This approach offers two key benefits:
1.  **Ease of Extraction:** It simplifies the extraction of these self-contained shellcode blobs from the compiled driver. Once extracted, these position-independent or easily relocatable blobs can be directly written into the granularly allocated executable memory regions within the target kernel space.
2.  **Enhanced Obfuscation Input:** The creation of a single, large, and potentially complex monolithic function through inlining serves as an excellent input for the subsequent instruction substitution pass. The inherent intricacy of such a large function, when processed even by light obfuscation, can result in a final machine code output that is significantly more challenging to analyze. This makes it harder for an analyst to discern distinct functional blocks or reconstruct the original logical structure of the code.

---

These combined measures aim to significantly elevate the difficulty for fingerprinting solutions to reliably detect or generate stable signatures for the hardware ID spoofing toolkit, thereby enhancing its overall stealth and longevity.

### 5. Conclusion
The techniques described offer advanced methods for stealthily spoofing hardware identifiers and disrupting WMI queries by manipulating low-level Windows kernel structures and inter-process communication mechanisms. These methods rely on intricate knowledge of undocumented or version-specific details of the Windows operating system, requiring careful reverse engineering and dynamic resolution of addresses and offsets. While designed to bypass common detection methods, they are inherently complex and carry risks of system instability if not implemented with extreme care and thorough testing on target environments. These methods highlight the ongoing cat-and-mouse game between those attempting to fingerprint systems and those aiming to evade such detection.

---
