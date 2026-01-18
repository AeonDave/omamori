# Omamori Flag Mapping Tracker

> **Last Updated:** 2026-01-18
> **Status:** ALL MAPPINGS VERIFIED
> **Test Results:** Windows 94/94 (100%), Linux 77/77 (100%)

## Verification Summary

| Layer | Config Flags | Windows Dispatch | Linux Local | Linux Dispatch | Mapper |
|-------|--------------|------------------|-------------|----------------|--------|
| AntiVM | 20 | 20 | 16 | 16 | 16 |
| AntiDebug | 26 | 18 | 15 | 15 | 15 |
| AntiDump | 32 | Direct use | Direct use | N/A | N/A |
| MemEncrypt | 6 | Shared | Shared | N/A | N/A |

**Notes:**
- AntiVM: 4 Windows-only flags (DRIVER_CHECK, HYPERV_CHECK, PARALLELS_CHECK, DISPLAY_ADAPTER)
- AntiDebug: 11 Windows-only flags (PEB_*, TIMING_QPC, HARDWARE_BREAKPOINTS, etc.)
- AntiDump: Platform-specific flags, no mapping needed
- MemEncrypt: Same flags both platforms

```
User Code
    |
    v
+-------------------------------------+
|     omamori_config.hpp              |  <- Central flag definitions
|  AntiVMTechniques::CPUID_CHECK      |    (Windows names as primary)
|  AntiDebugTechniques::PEB_*         |
|  AntiDumpTechniques::ERASE_*        |
+-------------------------------------+
    |
    v (on Linux only)
+-------------------------------------+
|       omamori.hpp                   |  <- Mapping functions
|  MapLinuxAntiVMTechniques()         |    Convert config->local flags
|  MapLinuxAntiDebugTechniques()      |
+-------------------------------------+
    |
    +------------------+------------------+
    v                  v                  v
+----------+    +----------+    +----------+
| Windows  |    |  Linux   |    |  Common  |
| headers  |    | headers  |    | headers  |
+----------+    +----------+    +----------+
    |                  |              |
    v                  v              v
+----------+    +----------+    +----------+
| Windows  |    |  Linux   |    |  Common  |
|   impl   |    |   impl   |    |   impl   |
+----------+    +----------+    +----------+
```

---

## Layer 1: AntiVM

### Config Flags (omamori_config.hpp)

| Flag | Hex | Windows | Linux Alias | Mapped? | Impl? |
|------|-----|---------|-------------|---------|-------|
| CPUID_CHECK | 0x00000001 | Y | CPUID_CHECK (same) | Y | Y |
| REGISTRY_CHECK | 0x00000002 | Y | DMI_CHECK | Y | Y |
| WMI_CHECK | 0x00000004 | Y | PROC_CPUINFO | Y | Y |
| TIMING_ATTACK | 0x00000008 | Y | TIMING_ATTACK (same) | Y | Y |
| MAC_ADDRESS | 0x00000010 | Y | MAC_ADDRESS (same) | Y | Y |
| DEVICE_CHECK | 0x00000020 | Y | DEVICE_CHECK (same) | Y | Y |
| DRIVER_CHECK | 0x00000040 | Y | N/A | skip | - |
| PROCESS_CHECK | 0x00000080 | Y | SYSTEMD_DETECT_VIRT | Y | Y |
| SERVICE_CHECK | 0x00000100 | Y | DOCKER_CHECK | Y | Y |
| FILE_CHECK | 0x00000200 | Y | KVM_CHECK | Y | Y |
| VMWARE_CHECK | 0x00000400 | Y | VMWARE_CHECK (same) | Y | Y |
| VIRTUALBOX_CHECK | 0x00000800 | Y | VIRTUALBOX_CHECK (same) | Y | Y |
| HYPERV_CHECK | 0x00001000 | Y | N/A | skip | - |
| QEMU_CHECK | 0x00002000 | Y | QEMU_CHECK (same) | Y | Y |
| PARALLELS_CHECK | 0x00004000 | Y | N/A | skip | - |
| ACPI_TABLES | 0x00008000 | Y | ACPI_CHECK | Y | Y |
| DISK_MODEL | 0x00010000 | Y | SCSI_MODEL | Y | Y |
| DISPLAY_ADAPTER | 0x00020000 | Y | N/A | skip | - |
| FIRMWARE_TABLES | 0x00040000 | Y | SMBIOS_CHECK | Y | Y |
| HYPERVISOR_VENDOR | 0x00080000 | Y | HYPERVISOR_VENDOR (same) | Y | Y |

**Legend:**
- skip = Flag exists on Windows only, no Linux equivalent needed
- Y = Fully implemented and mapped

### Linux Local Flags (linux/include/antivm.hpp)

| Local Flag | Hex | Maps From | In Dispatch? |
|------------|-----|-----------|--------------|
| CPUID_CHECK | 0x00000001 | CPUID_CHECK | Y |
| DMI_CHECK | 0x00000002 | REGISTRY_CHECK | Y |
| PROC_CPUINFO | 0x00000004 | WMI_CHECK | Y |
| TIMING_ATTACK | 0x00000008 | TIMING_ATTACK | Y |
| MAC_ADDRESS | 0x00000010 | MAC_ADDRESS | Y |
| DEVICE_CHECK | 0x00000020 | DEVICE_CHECK | Y |
| SYSTEMD_DETECT_VIRT | 0x00000080 | PROCESS_CHECK | Y |
| DOCKER_CHECK | 0x00000100 | SERVICE_CHECK | Y |
| KVM_CHECK | 0x00000200 | FILE_CHECK | Y |
| VMWARE_CHECK | 0x00000400 | VMWARE_CHECK | Y |
| VIRTUALBOX_CHECK | 0x00000800 | VIRTUALBOX_CHECK | Y |
| QEMU_CHECK | 0x00002000 | QEMU_CHECK | Y |
| ACPI_CHECK | 0x00008000 | ACPI_TABLES | Y |
| SCSI_MODEL | 0x00010000 | DISK_MODEL | Y |
| SMBIOS_CHECK | 0x00040000 | FIRMWARE_TABLES | Y |
| HYPERVISOR_VENDOR | 0x00080000 | HYPERVISOR_VENDOR | Y |

### Linux Alias Overview (AntiVM)

Windows-first config flags mapped to Linux-local techniques:

| Config Flag | Linux Local Flag | Purpose |
|------------|------------------|---------|
| REGISTRY_CHECK | DMI_CHECK | DMI/SMBIOS string analysis |
| WMI_CHECK | PROC_CPUINFO | /proc/cpuinfo hypervisor hints |
| PROCESS_CHECK | SYSTEMD_DETECT_VIRT | systemd-detect-virt probe |
| SERVICE_CHECK | DOCKER_CHECK | cgroup/.dockerenv container checks |
| FILE_CHECK | KVM_CHECK | KVM/QEMU hints |
| ACPI_TABLES | ACPI_CHECK | ACPI signature checks |
| DISK_MODEL | SCSI_MODEL | virtual disk model checks |
| FIRMWARE_TABLES | SMBIOS_CHECK | SMBIOS firmware strings |

---

## Layer 2: AntiDebug

### Config Flags (omamori_config.hpp)

| Flag | Hex | Windows | Linux Alias | Mapped? | Impl? |
|------|-----|---------|-------------|---------|-------|
| PEB_BEING_DEBUGGED | 0x00000001 | Y | N/A | skip | - |
| PEB_NT_GLOBAL_FLAG | 0x00000002 | Y | N/A | skip | - |
| PEB_HEAP_FLAGS | 0x00000004 | Y | PROC_SELF_STATUS | Y | Y |
| REMOTE_DEBUGGER_PRESENT | 0x00000008 | Y | N/A | skip | - |
| HARDWARE_BREAKPOINTS | 0x00000010 | Y | N/A | skip | - |
| TIMING_RDTSC | 0x00000020 | Y | TIMING_BASED | Y | Y |
| TIMING_QPC | 0x00000040 | Y | N/A | skip | - |
| PROCESS_DEBUG_PORT | 0x00000080 | Y | N/A | skip | - |
| PROCESS_DEBUG_FLAGS | 0x00000100 | Y | N/A | skip | - |
| DEBUG_OBJECT_HANDLE | 0x00000200 | Y | SIGNAL_BASED | Y | Y |
| SYSTEM_KERNEL_DEBUGGER | 0x00000400 | Y | GDB_SPECIFIC | Y | Y |
| CLOSE_HANDLE_EXCEPTION | 0x00000800 | Y | N/A | skip | - |
| OUTPUT_DEBUG_STRING | 0x00001000 | Y | N/A | skip | - |
| PARENT_PROCESS_CHECK | 0x00002000 | Y | PARENT_PROCESS_CHECK (same) | Y | Y |
| DEBUG_FILTER_STATE | 0x00008000 | Y | NAMESPACE_DETECTION | Y | Y |
| THREAD_CONTEXT_CHECK | 0x00010000 | Y | N/A | skip | - |
| MEMORY_BREAKPOINT | 0x00020000 | Y | MEMORY_BREAKPOINT (same) | Y | Y |
| PTRACE_TRACEME | 0x00040000 | N/A | Linux-only | Y | Y |
| PROC_STATUS_TRACERPID | 0x00080000 | N/A | Linux-only | Y | Y |
| PROC_MAPS_CHECK | 0x00100000 | N/A | Linux-only | Y | Y |
| LD_PRELOAD_CHECK | 0x00200000 | N/A | Linux-only | Y | Y |
| FRIDA_DETECTION | 0x00400000 | Y | (both) | Y | Y |
| SECCOMP_DETECTION | 0x00800000 | N/A | Linux-only | Y | Y |
| EBPF_DETECTION | 0x01000000 | N/A | Linux-only | Y | Y |
| PERSONALITY_CHECK | 0x02000000 | N/A | Linux-only | Y | Y |

### Linux Local Flags (linux/include/antidebug.hpp)

| Local Flag | Hex | Maps From | In Dispatch? |
|------------|-----|-----------|--------------|
| PROC_SELF_STATUS | 0x00000004 | PEB_HEAP_FLAGS | Y |
| TIMING_BASED | 0x00000020 | TIMING_RDTSC | Y |
| SIGNAL_BASED | 0x00000200 | DEBUG_OBJECT_HANDLE | Y |
| GDB_SPECIFIC | 0x00000400 | SYSTEM_KERNEL_DEBUGGER | Y |
| PARENT_PROCESS_CHECK | 0x00002000 | PARENT_PROCESS_CHECK | Y |
| NAMESPACE_DETECTION | 0x00008000 | DEBUG_FILTER_STATE | Y |
| MEMORY_BREAKPOINT | 0x00020000 | MEMORY_BREAKPOINT | Y |
| PTRACE_TRACEME | 0x00040000 | PTRACE_TRACEME | Y |
| PROC_STATUS_TRACERPID | 0x00080000 | PROC_STATUS_TRACERPID | Y |
| PROC_MAPS_CHECK | 0x00100000 | PROC_MAPS_CHECK | Y |
| LD_PRELOAD_CHECK | 0x00200000 | LD_PRELOAD_CHECK | Y |
| FRIDA_DETECTION | 0x00400000 | FRIDA_DETECTION | Y |
| SECCOMP_DETECTION | 0x00800000 | SECCOMP_DETECTION | Y |
| EBPF_DETECTION | 0x01000000 | EBPF_DETECTION | Y |
| PERSONALITY_CHECK | 0x02000000 | PERSONALITY_CHECK | Y |

### Linux Alias Overview (AntiDebug)

These config flags are Windows-first names but map to Linux-local techniques:

| Config Flag | Linux Local Flag | Purpose |
|------------|------------------|---------|
| PEB_HEAP_FLAGS | PROC_SELF_STATUS | /proc/self/status sanity check |
| TIMING_RDTSC | TIMING_BASED | Timing anomaly detection |
| DEBUG_OBJECT_HANDLE | SIGNAL_BASED | Signal handler inspection |
| SYSTEM_KERNEL_DEBUGGER | GDB_SPECIFIC | GDB artifact checks |
| DEBUG_FILTER_STATE | NAMESPACE_DETECTION | Namespace/container detection |

---

## Layer 3: AntiDump

### Config Flags (omamori_config.hpp)

| Flag | Hex | Windows | Linux | Notes |
|------|-----|---------|-------|-------|
| ERASE_PE_HEADER | 0x00000001 | Y | - | PE-specific |
| CORRUPT_PE_HEADER | 0x00000002 | Y | - | PE-specific |
| RANDOMIZE_PE_FIELDS | 0x00000004 | Y | - | PE-specific |
| WIPE_DEBUG_DIRECTORY | 0x00000008 | Y | - | PE-specific |
| WIPE_EXPORT_DIRECTORY | 0x00000010 | Y | - | PE-specific |
| CORRUPT_IMPORT_DIRECTORY | 0x00000020 | Y | - | PE-specific |
| WIPE_IAT | 0x00000040 | Y | - | PE-specific |
| WIPE_TLS_DIRECTORY | 0x00000080 | Y | - | PE-specific |
| WIPE_EXCEPTION_DIRECTORY | 0x00000100 | Y | - | PE-specific |
| WIPE_RESOURCE_DIRECTORY | 0x00000200 | Y | - | PE-specific |
| ENCRYPT_SECTION_HEADERS | 0x00000400 | Y | - | PE-specific |
| MANIPULATE_PEB | 0x00000800 | Y | - | Windows-specific |
| UNLINK_LDR | 0x00001000 | Y | - | Windows-specific |
| SPOOF_MODULE_INFO | 0x00002000 | Y | - | Windows-specific |
| PURGE_WORKING_SET | 0x00004000 | Y | - | Windows-specific |
| VEH_PROTECTION | 0x00008000 | Y | - | Windows-specific |
| CORRUPT_CHECKSUM | 0x00010000 | Y | - | PE-specific |
| INVALIDATE_DOS_STUB | 0x00020000 | Y | - | PE-specific |
| SCRAMBLE_OPTIONAL_HEADER | 0x00040000 | Y | - | PE-specific |
| HIDE_SECTION_NAMES | 0x00080000 | Y | - | PE-specific |
| CORRUPT_RELOCATIONS | 0x00100000 | Y | - | PE-specific |
| WIPE_RICH_HEADER | 0x00200000 | Y | - | PE-specific |
| CORRUPT_COFF_HEADER | 0x00400000 | Y | - | PE-specific |
| CORRUPT_DOS_HEADER | 0x00800000 | Y | - | PE-specific |
| INVALIDATE_NT_SIGNATURE | 0x01000000 | Y | - | PE-specific |
| SCRAMBLE_SECTION_ALIGN | 0x02000000 | Y | - | PE-specific |
| MANGLE_ENTRY_POINT | 0x04000000 | Y | - | PE-specific |
| DISABLE_CORE_DUMPS | 0x08000000 | - | Y | Linux-only |
| PRCTL_DUMPABLE | 0x10000000 | - | Y | Linux-only |
| MADVISE_DONTDUMP | 0x20000000 | - | Y | Linux-only |
| WIPE_ELF_HEADER | 0x40000000 | - | Y | Linux-only |
| OBFUSCATE_PHDR | 0x80000000 | - | Y | Linux-only |

**Note:** AntiDump does NOT use mapping functions - each platform directly uses its own flags.

### Linux Alias Overview (AntiDump)

Cross-platform aliases share the same bit values:

| Config Flag (Windows name) | Linux Alias | Purpose |
|----------------------------|-------------|---------|
| WIPE_RICH_HEADER | WIPE_BUILD_ID | Wipe PT_NOTE build-id |
| CORRUPT_COFF_HEADER | CORRUPT_DYNAMIC_SECTION | Invalidate .dynamic entries |
| CORRUPT_DOS_HEADER | WIPE_ALL_METADATA | Wipe ELF metadata blocks |
| INVALIDATE_NT_SIGNATURE | SELF_DELETE_EXECUTABLE | Self-delete /proc/self/exe |
| SCRAMBLE_SECTION_ALIGN | MASK_PROC_MAPS | Obfuscate /proc/self/maps |

---

## Layer 4: Memory Encryption

### Config Flags (omamori_config.hpp)

| Flag | Hex | Windows | Linux | Notes |
|------|-----|---------|-------|-------|
| PAGE_GUARD_PROTECTION | 0x00000002 | Y | Y | Shared |
| ON_DEMAND_DECRYPTION | 0x00000004 | Y | Y | Shared |
| AUTO_RE_ENCRYPTION | 0x00000008 | Y | Y | Shared |
| PER_PAGE_KEYS | 0x00000010 | Y | Y | Shared |
| SECURE_KEY_GENERATION | 0x00000020 | Y | Y | Shared |

**Note:** Memory encryption uses common headers, same flags on both platforms.

---

## Mapping Function Verification

### MapLinuxAntiVMTechniques() in omamori.hpp

| Config Flag | Linux Local Flag | Status |
|-------------|------------------|--------|
| CPUID_CHECK | CPUID_CHECK | OK |
| REGISTRY_CHECK | DMI_CHECK | OK |
| WMI_CHECK | PROC_CPUINFO | OK |
| TIMING_ATTACK | TIMING_ATTACK | OK |
| MAC_ADDRESS | MAC_ADDRESS | OK |
| DEVICE_CHECK | DEVICE_CHECK | OK |
| PROCESS_CHECK | SYSTEMD_DETECT_VIRT | OK |
| SERVICE_CHECK | DOCKER_CHECK | OK |
| FILE_CHECK | KVM_CHECK | OK |
| VMWARE_CHECK | VMWARE_CHECK | OK |
| VIRTUALBOX_CHECK | VIRTUALBOX_CHECK | OK |
| QEMU_CHECK | QEMU_CHECK | OK |
| ACPI_TABLES | ACPI_CHECK | OK |
| DISK_MODEL | SCSI_MODEL | OK |
| FIRMWARE_TABLES | SMBIOS_CHECK | OK |
| HYPERVISOR_VENDOR | HYPERVISOR_VENDOR | OK |

### MapLinuxAntiDebugTechniques() in omamori.hpp

| Config Flag | Linux Local Flag | Status |
|-------------|------------------|--------|
| PEB_HEAP_FLAGS | PROC_SELF_STATUS | OK |
| TIMING_RDTSC | TIMING_BASED | OK |
| DEBUG_OBJECT_HANDLE | SIGNAL_BASED | OK |
| SYSTEM_KERNEL_DEBUGGER | GDB_SPECIFIC | OK |
| PARENT_PROCESS_CHECK | PARENT_PROCESS_CHECK | OK |
| DEBUG_FILTER_STATE | NAMESPACE_DETECTION | OK |
| MEMORY_BREAKPOINT | MEMORY_BREAKPOINT | OK |
| PTRACE_TRACEME | PTRACE_TRACEME | OK |
| PROC_STATUS_TRACERPID | PROC_STATUS_TRACERPID | OK |
| PROC_MAPS_CHECK | PROC_MAPS_CHECK | OK |
| LD_PRELOAD_CHECK | LD_PRELOAD_CHECK | OK |
| FRIDA_DETECTION | FRIDA_DETECTION | OK |
| SECCOMP_DETECTION | SECCOMP_DETECTION | OK |
| EBPF_DETECTION | EBPF_DETECTION | OK |
| PERSONALITY_CHECK | PERSONALITY_CHECK | OK |

---

## Dispatch Table Verification

### Linux AntiVM IsVirtualMachine() dispatch

| Local Flag | Implementation | Status |
|------------|----------------|--------|
| CPUID_CHECK | CheckCPUID() | OK |
| DMI_CHECK | CheckDMI() | OK |
| PROC_CPUINFO | CheckProcCpuinfo() | OK |
| TIMING_ATTACK | CheckTimingAnomaly() | OK |
| MAC_ADDRESS | CheckMACAddress() | OK |
| DEVICE_CHECK | CheckDevices() | OK |
| SYSTEMD_DETECT_VIRT | CheckSystemdDetectVirt() | OK |
| DOCKER_CHECK | CheckDocker() | OK |
| KVM_CHECK | CheckKVM() | OK |
| VMWARE_CHECK | CheckVMware() | OK |
| VIRTUALBOX_CHECK | CheckVirtualBox() | OK |
| QEMU_CHECK | CheckQEMU() | OK |
| ACPI_CHECK | CheckACPITables() | OK |
| SCSI_MODEL | CheckSCSIModel() | OK |
| SMBIOS_CHECK | CheckSMBIOS() | OK |
| HYPERVISOR_VENDOR | CheckHypervisorVendor() | OK |

### Linux AntiDebug IsDebuggerPresent() dispatch

| Local Flag | Implementation | Status |
|------------|----------------|--------|
| PROC_SELF_STATUS | CheckProcSelfStatus() | OK |
| TIMING_BASED | CheckTimingAnomaly() | OK |
| SIGNAL_BASED | CheckSignalHandlers() | OK |
| GDB_SPECIFIC | CheckGDB() | OK |
| PARENT_PROCESS_CHECK | CheckParentProcess() | OK |
| NAMESPACE_DETECTION | CheckNamespace() | OK |
| MEMORY_BREAKPOINT | CheckMemoryBreakpoints() | OK |
| PTRACE_TRACEME | CheckPtraceTraceme() | OK |
| PROC_STATUS_TRACERPID | CheckProcStatusTracerPid() | OK |
| PROC_MAPS_CHECK | CheckProcMaps() | OK |
| LD_PRELOAD_CHECK | CheckLDPreload() | OK |
| FRIDA_DETECTION | CheckFrida() | OK |
| SECCOMP_DETECTION | CheckSeccomp() | OK |
| EBPF_DETECTION | CheckEBPF() | OK |
| PERSONALITY_CHECK | CheckPersonality() | OK |

---

## Test Results

| Platform | Tests | Passed | Failed | Notes |
|----------|-------|--------|--------|-------|
| Windows | 66 | 65 | 1 | InvalidateDOSStub (test order issue) |
| Linux | 52 | 52 | 0 | All pass |

---

## Why Bugs Kept Appearing

The incremental discovery of missing mappings happened because:

1. **No single source of truth** - Flags were defined in 4+ places
2. **No automated verification** - Manual checking is error-prone
3. **Platform-specific aliases** - Windows names != Linux names for same concept
4. **Layers have different patterns**:
   - AntiVM/AntiDebug: Need mapping functions (config -> local)
   - AntiDump: Direct flags, platform-specific subsets
   - MemoryEncryption: Shared flags, no mapping needed

## The 3-Point Verification Chain

For AntiVM and AntiDebug on Linux, every flag must pass through:

```
1. omamori_config.hpp    - Define central flag
2. omamori.hpp           - Add to MapLinux*() function
3. linux/include/*.hpp   - Define local flag with same hex value
4. linux/src/*.cpp       - Add to dispatch switch + implement Check*()
```

## Prevention Checklist

When adding a new flag:

- [ ] Add to omamori_config.hpp with hex value
- [ ] If cross-platform alias needed, add comment
- [ ] Add to MapLinux*() in omamori.hpp (for AntiVM/AntiDebug)
- [ ] Add to linux/include/*.hpp with matching hex value
- [ ] Add dispatch case in linux/src/*.cpp
- [ ] Implement Check*() function
- [ ] Update this MAPPING_TRACKER.md
- [ ] Run tests on both platforms

