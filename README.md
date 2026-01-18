# Omamori - Protection Against Unseen Evil

---

![Omamori](omamori_logo.png)

A cross-platform protection library implementing advanced anti-debugging, anti-dumping, anti-virtualization, and memory encryption techniques for Windows and Linux.

**Platform Support:** Windows | Linux | **Architecture:** x86 | x64 | **License:** MIT | **C++ Standard:** 17

**Compilers:** MSVC (Visual Studio 2019+) | MinGW-w64 (GCC 10+) | GCC (Linux 10+) | Clang (12+)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Granular Configuration](#selective-protection)
  - [Technique Bitmasks](#technique-bitmasks)
  - [Builder Pattern API](#builder-pattern-api)
  - [Preset Configurations](#preset-configurations)
  - [Detection with Specific Techniques](#detection-with-specific-techniques)
- [Examples](#examples)
  - [Granular Configuration Examples](#granular-configuration-examples)
- [Excluded Techniques](#excluded-techniques)
- [API Reference](#api-reference)
- [Build Instructions](#build-instructions)
- [Testing](#testing)
- [Performance](#performance)
- [Security Considerations](#security-considerations)
- [Technical Details](#technical-details)

---

## Overview

Omamori is a production-ready software protection library designed to defend applications against reverse engineering, debugging, memory dumping, and virtualized analysis environments. It implements over 60 modern protection techniques across Windows and Linux platforms.

### Protection Stack

| Layer | Component | Key features |
|---:|:---|:---|
| Layer 4 | Memory Encryption | Transparent on-demand encryption; **ChaCha20-like stream cipher** (20-round core); Page-level protection (PROT_NONE / PAGE_NOACCESS); Automatic SIGSEGV / VEH handler |
| Layer 3 | Anti-Dump | **30+ Windows / 15+ Linux techniques**; PE/ELF header manipulation; **Rich Header wiping**; **Section encryption**; **Directory wiping**; **Code integrity hashing**; **MADV_DONTDUMP**; **Working set purging**; PEB/LDR unlinking; Continuous re-corruption |
| Layer 2 | Anti-Debug | Multi-vector debugger detection & prevention; PEB / TEB inspection (50+ checks); Hardware breakpoint detection (DR0-DR7); ETW Patching; AMSI Bypass; ptrace self-attach (Linux); Framework detection (GDB, Frida, LLDB, x64dbg) |
| Layer 1 | Anti-Virtualization | VM & container detection; **Hypervisor CPUID Vendor**; **ACPI/SMBIOS Tables**; **Firmware Tables**; MAC address fingerprinting; Container checks (cgroup, /.dockerenv); VM artifacts (VMware, VirtualBox, Hyper-V) |
| Base | System Integration | **Direct & Indirect syscalls** (Windows); **Halo's Gate** SSN resolution; Compile-time secure string encryption (XOR); Cross-platform abstraction layer |

---

## Features

### Cross-Platform Protection

- Unified API for Windows and Linux
- Platform-specific optimizations
- Compile-time string encryption
- Runtime memory protection
- **Direct & Indirect syscalls** (Windows) - EDR/Hook evasion
- **Halo's Gate** - SSN resolution when ntdll.dll is hooked
- **ChaCha20-like encryption** - Stream-cipher-based memory protection

### Layer 1: Anti-Virtualization

> **Stability First:** All detection methods are selected to avoid false positives.
> No timing-based detection is used by default.

**Linux (16 techniques):**

- CPUID hypervisor bit detection
- **Hypervisor CPUID Vendor** - reads hypervisor signature (VMwareVMware, KVMKVMKVM, etc.)
- DMI/SMBIOS string analysis (/sys/class/dmi/id/*)
- **ACPI Tables** - DSDT/FACP table signatures
- **SCSI/Disk Model** - virtual disk model names
- MAC address fingerprinting (VMware, VirtualBox, Hyper-V, Parallels, KVM)
- VM device detection (/dev/vmware, /dev/vboxguest, etc.)
- VMware-specific artifacts
- VirtualBox-specific signatures
- KVM detection
- QEMU detection
- Docker container detection (/.dockerenv)
- cgroup-based container detection
- systemd-detect-virt integration
- /proc/modules kernel module scan

**Windows (20 techniques):**

- CPUID hypervisor bit detection
- **Hypervisor CPUID Vendor** - reads VMwareVMware, VBoxVBoxVBox, Microsoft Hv, etc.
- **ACPI Tables** - DSDT/FADT/RSDT registry signatures
- **Disk Model** - SCSI disk identifier strings
- **Display Adapter** - virtual GPU detection (VMware SVGA, VBox Graphics)
- **Firmware Tables** - SMBIOS raw data via GetSystemFirmwareTable
- Registry checks (HARDWARE\\DEVICEMAP\\Scsi, BIOS info)
- MAC address detection (00:05:69, 00:0C:29, 08:00:27, etc.)
- Device driver detection (VBoxGuest, VMware tools)
- Process detection (vmtoolsd, vboxservice)
- Service detection (VMware services, VBox services)
- File system artifacts (C:\\Program Files\\VMware)
- WMI queries (Win32_ComputerSystem, BIOS manufacturer)
- Hyper-V specific detection
- Parallels detection
- QEMU detection

### Layer 2: Anti-Debug

**60+ detection techniques including:**

**Windows (20+ techniques):**

- PEB/TEB inspection (BeingDebugged, NtGlobalFlag, heap flags)
- Hardware breakpoint detection (DR0-DR7 registers)
- API-based detection (CheckRemoteDebuggerPresent, NtQueryInformationProcess)
- Exception-based detection (CloseHandle, OutputDebugString)
- Framework detection (x64dbg, OllyDbg, WinDbg)
- Parent process verification
- Kernel debugger detection (NtQuerySystemInformation)
- **ETW Patching** - Disables Event Tracing for Windows
- **AMSI Bypass** - Patches AmsiScanBuffer to return clean
- **INT 2D Check** - Interrupt-based debugger detection
- **NtSetDebugFilterState** - Debug filter state manipulation
- **Thread Context Manipulation** - DR7 persistence check
- **Memory Breakpoint Scan** - Detects INT3 (0xCC) in code

**Linux (15+ techniques):**

- ptrace manipulation (TRACEME, self-attach)
- /proc filesystem checks (TracerPid, maps, status)
- Framework detection (Frida, GDB, LLDB)
- Environment analysis (LD_PRELOAD, debug variables)
- Parent process verification
- Signal handler inspection
- **Seccomp Detection** - Detects sandbox/seccomp filtering
- **eBPF Detection** - Detects eBPF tracing programs
- **Namespace Detection** - Container/namespace isolation check
- **Memory Breakpoint Scan** - INT3 detection in executable code
- **Personality Check** - ADDR_NO_RANDOMIZE (ASLR disabled) detection
- Background monitoring thread with customizable intervals

### Layer 3: Anti-Dump

**Windows (30+ techniques):**

- PE header erasure/corruption
- DOS stub invalidation
- **Rich Header wiping** - Removes compiler fingerprints
- **Section header encryption** - XOR-encrypted section table
- **Directory table wiping** - Debug, Export, Import, TLS, Exception, Resource
- **COFF header corruption** - TimeDateStamp, Symbols invalidation
- **Optional header scrambling** - Stack/Heap sizes, Loader flags
- **Section name hiding** - Zeroed section names
- **PE checksum corruption** - Invalid checksum
- **Entry point mangling** - XOR obfuscated entry point
- **Section alignment scrambling** - Invalid alignment values
- PEB/LDR module unlinking
- VEH-based memory protection
- **Working set purging** - EmptyWorkingSet() for anti-forensics
- **Critical page locking** - VirtualLock for memory pinning
- **Code integrity hashing** - FNV-1a hash for tamper detection
- Continuous re-corruption thread
- PAGE_NOACCESS / PAGE_GUARD protection

**Linux (15+ techniques):**

- ELF magic bytes corruption
- ELF header erasure
- **Program header invalidation** - e_phoff, e_phnum zeroing
- **Section header scrambling** - e_shoff, e_shnum randomization
- **Dynamic string table wiping** - e_shstrndx zeroing
- **Build ID wiping** - PT_NOTE section zeroing
- **Dynamic section corruption** - DT_STRTAB, DT_SYMTAB invalidation
- **GOT corruption** - (optional, careful use)
- **MADV_DONTDUMP** - Exclude regions from core dumps
- **coredump_filter** - /proc/self/coredump_filter = 0
- **Signal handler protection** - SIGABRT, SIGQUIT, SIGBUS handlers
- **ptrace protection** - Self-ptrace for anti-dump
- Core dump prevention (setrlimit RLIMIT_CORE + prctl PR_SET_DUMPABLE)
- SIGSEGV exception handling
- /proc/self protection
- **Memory mapping tricks** - Decoy PROT_NONE regions
- Continuous re-corruption thread

### Layer 4: Memory Encryption

**Transparent on-demand encryption:**

- Page-level protection with signal/exception handlers
- **ChaCha20-like stream cipher** (20-round core)
- Automatic decryption on memory access (SIGSEGV/VEH)
- Per-page unique encryption keys (CryptGenRandom + RDTSC entropy)
- Automatic re-encryption thread (configurable timeout)
- Manual re-encryption (call `ProtectAndEncrypt` after access)
- Zero application code changes
- Template-based RAII interface
- Protects credentials, license keys, sensitive data
- **Quarter-round mixing** for cryptographic strength

---

## Quick Start

### Linux Build

```bash
# Clone repository
git clone <repository>
cd omamori

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run tests
./omamori_test_linux

# Run example
./omamori_example_linux
```

### Windows Build

The library is compatible with both **MSVC** and **MinGW-w64** compilers. Conditional compilation guards ensure full compatibility.

```bash
# Using Visual Studio (MSVC)
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# Using MinGW-w64 (GCC)
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
mingw32-make

# Manual compilation with MinGW (without CMake)
g++ -std=c++17 -DOMAMORI_PLATFORM_WINDOWS -o your_app.exe your_app.cpp ^
    windows/src/*.cpp -I include -I common/include -I windows/include ^
    -lntdll -liphlpapi -lpsapi -lws2_32 -static
```

> **Note:** Some advanced features (SEH exception-based detection, I/O port checks) are only available with MSVC. When compiled with MinGW, the library gracefully falls back to alternative detection methods, maintaining full protection coverage.

### Basic Usage

```cpp
#include <omamori.hpp>

int main() {
    // Initialize protection system (Production preset by default)
    Omamori::Initialize();
  
    // Check for debugger presence
    if (Omamori::IsDebugged()) {
        Omamori::TerminateIfDebugged();
    }
  
    // Your application code
    ProcessSensitiveData();
  
    return 0;
}
```

### Advanced Usage with Granular Configuration

```cpp
#include <omamori.hpp>
using namespace Omamori;

int main() {
    // Create custom configuration using builder pattern
    auto config = ProtectionConfig()
        .WithAntiVM(false)                                    // Disable VM detection
        .WithAntiDebug(true, AntiDebugTechniques::FAST)       // Fast checks only
        .WithAntiDebugThread(true, 500)                       // Check every 500ms
        .WithAntiDump(true, AntiDumpTechniques::STANDARD)     // Standard protection
        .WithMemoryEncryption(true)                           // Enable encryption layer
        .WithCallback([](const char* layer, const char* tech) {
            std::cerr << "Security: " << layer << "/" << tech << std::endl;
        });

    // Auto-init memory encryption if desired
    config.memory_auto_init = true;
    
    // Initialize with custom config
    Omamori::Initialize(config);
    
    // Quick debugger check with specific technique
    if (Omamori::IsDebugged(AntiDebugTechniques::PEB_BEING_DEBUGGED)) {
        HandleDebuggerDetected();
    }
    
    // Safe VM check (no timing-based detection)
    if (Omamori::IsInVM(AntiVMTechniques::SAFE)) {
        std::cout << "Running in VM" << std::endl;
    }
    
    // Your application code
    ProcessSensitiveData();
    
    return 0;
}
```

### One-Liner Presets

```cpp
// Maximum security (all 4 layers, all techniques)
Omamori::Initialize(ProtectionConfig::MaximumProtection());

// Production deployment (Anti-Debug + Anti-Dump, no Anti-VM)
Omamori::Initialize(ProtectionConfig::Production());

// Stealth mode (no timing-based checks, low profile)
Omamori::Initialize(ProtectionConfig::Stealth());

// Only one layer
Omamori::Initialize(ProtectionConfig::LayerOnly(2));  // Anti-Debug only

// Only one technique
Omamori::Initialize(ProtectionConfig::SingleTechnique(2, 
    AntiDebugTechniques::PEB_BEING_DEBUGGED));
```

---

## Selective Protection

### Overview

Omamori provides **four independent protection layers** with **granular technique control**. Each layer can be enabled or disabled, and within each layer you can select exactly which techniques to activate using bitmasks.

This gives you fine-grained control over:
- **Which layers** are active
- **Which techniques** within each layer are used
- **Performance vs. security** trade-offs

### Configuration Structure

```cpp
struct ProtectionConfig {
    // Layer 1: Anti-Virtualization
    bool enable_antivm = false;
    uint32_t antivm_techniques = AntiVMTechniques::ALL;
    
    // Layer 2: Anti-Debug  
    bool enable_antidebug = true;
    uint32_t antidebug_techniques = AntiDebugTechniques::ALL;
    bool enable_antidebug_thread = true;
    uint32_t antidebug_check_interval_ms = 100;
    bool antidebug_terminate_on_detect = true;
    
    // Layer 3: Anti-Dump
    bool enable_antidump = true;
    uint32_t antidump_techniques = AntiDumpTechniques::ALL;
    bool antidump_continuous = false;
    
    // Layer 4: Memory Encryption
    bool enable_memory_encryption = false;
    uint32_t memory_encryption_techniques = MemoryEncryptionTechniques::ALL;
    bool memory_auto_init = false;
    
    // Callback for custom detection handling
    void (*on_detection)(const char* layer, const char* technique) = nullptr;
};
```

### Technique Bitmasks

Each layer has its own namespace with technique flags that can be combined with bitwise OR (`|`).

#### Layer 1: Anti-VM Techniques

```cpp
namespace AntiVMTechniques {
    // Individual techniques (Windows names; Linux maps to local equivalents)
    constexpr uint32_t CPUID_CHECK       = 1 << 0;   // CPUID hypervisor bit
    constexpr uint32_t REGISTRY_CHECK    = 1 << 1;   // Windows registry checks (Linux: DMI)
    constexpr uint32_t WMI_CHECK         = 1 << 2;   // Windows WMI checks (Linux: /proc/cpuinfo)
    constexpr uint32_t TIMING_ATTACK     = 1 << 3;   // Timing anomaly
    constexpr uint32_t MAC_ADDRESS       = 1 << 4;   // VM MAC prefixes
    constexpr uint32_t DEVICE_CHECK      = 1 << 5;   // Device node checks
    constexpr uint32_t DRIVER_CHECK      = 1 << 6;   // Windows drivers (Win only)
    constexpr uint32_t PROCESS_CHECK     = 1 << 7;   // Windows processes (Linux: systemd-detect-virt)
    constexpr uint32_t SERVICE_CHECK     = 1 << 8;   // Windows services (Linux: Docker/cgroup)
    constexpr uint32_t FILE_CHECK        = 1 << 9;   // Windows files (Linux: KVM hints)
    constexpr uint32_t VMWARE_CHECK      = 1 << 10;  // VMware-specific
    constexpr uint32_t VIRTUALBOX_CHECK  = 1 << 11;  // VirtualBox-specific
    constexpr uint32_t HYPERV_CHECK      = 1 << 12;  // Hyper-V (Win only)
    constexpr uint32_t QEMU_CHECK        = 1 << 13;  // QEMU-specific
    constexpr uint32_t PARALLELS_CHECK   = 1 << 14;  // Parallels (Win only)
    constexpr uint32_t ACPI_TABLES       = 1 << 15;  // ACPI table signatures
    constexpr uint32_t DISK_MODEL        = 1 << 16;  // Disk model strings
    constexpr uint32_t DISPLAY_ADAPTER   = 1 << 17;  // GPU adapter checks (Win only)
    constexpr uint32_t FIRMWARE_TABLES   = 1 << 18;  // SMBIOS firmware strings
    constexpr uint32_t HYPERVISOR_VENDOR = 1 << 19;  // CPUID hypervisor vendor

    // Presets
    constexpr uint32_t SAFE = CPUID_CHECK | REGISTRY_CHECK | MAC_ADDRESS | DEVICE_CHECK |
                              PROCESS_CHECK | SERVICE_CHECK | FILE_CHECK |
                              ACPI_TABLES | DISK_MODEL | FIRMWARE_TABLES |
                              HYPERVISOR_VENDOR;
    constexpr uint32_t ALL  = 0xFFFFFFFF;
}
```

#### Layer 2: Anti-Debug Techniques

```cpp
namespace AntiDebugTechniques {
    // Windows techniques
    constexpr uint32_t PEB_BEING_DEBUGGED     = 1 << 0;
    constexpr uint32_t PEB_NT_GLOBAL_FLAG     = 1 << 1;
    constexpr uint32_t PEB_HEAP_FLAGS         = 1 << 2;  // Linux alias: PROC_SELF_STATUS
    constexpr uint32_t REMOTE_DEBUGGER_PRESENT= 1 << 3;
    constexpr uint32_t HARDWARE_BREAKPOINTS   = 1 << 4;
    constexpr uint32_t TIMING_RDTSC           = 1 << 5;  // Linux alias: TIMING_BASED
    constexpr uint32_t TIMING_QPC             = 1 << 6;
    constexpr uint32_t PROCESS_DEBUG_PORT     = 1 << 7;
    constexpr uint32_t PROCESS_DEBUG_FLAGS    = 1 << 8;
    constexpr uint32_t DEBUG_OBJECT_HANDLE    = 1 << 9;  // Linux alias: SIGNAL_BASED
    constexpr uint32_t SYSTEM_KERNEL_DEBUGGER = 1 << 10; // Linux alias: GDB_SPECIFIC
    constexpr uint32_t CLOSE_HANDLE_EXCEPTION = 1 << 11;
    constexpr uint32_t OUTPUT_DEBUG_STRING    = 1 << 12;
    constexpr uint32_t PARENT_PROCESS_CHECK   = 1 << 13;
    constexpr uint32_t INT_2D_CHECK           = 1 << 14;
    constexpr uint32_t DEBUG_FILTER_STATE     = 1 << 15; // Linux alias: NAMESPACE_DETECTION
    constexpr uint32_t THREAD_CONTEXT_CHECK   = 1 << 16;
    constexpr uint32_t MEMORY_BREAKPOINT      = 1 << 17;

    // Linux-specific
    constexpr uint32_t PTRACE_TRACEME         = 1 << 18;
    constexpr uint32_t PROC_STATUS_TRACERPID  = 1 << 19;
    constexpr uint32_t PROC_MAPS_CHECK        = 1 << 20;
    constexpr uint32_t LD_PRELOAD_CHECK       = 1 << 21;
    constexpr uint32_t FRIDA_DETECTION        = 1 << 22;
    constexpr uint32_t SECCOMP_DETECTION      = 1 << 23;
    constexpr uint32_t EBPF_DETECTION         = 1 << 24;
    constexpr uint32_t PERSONALITY_CHECK      = 1 << 25;

    // Presets
    constexpr uint32_t FAST    = PEB_BEING_DEBUGGED | PEB_NT_GLOBAL_FLAG | REMOTE_DEBUGGER_PRESENT |
                                PROCESS_DEBUG_PORT | PROCESS_DEBUG_FLAGS | PTRACE_TRACEME |
                                PROC_STATUS_TRACERPID;
    constexpr uint32_t STEALTH = PEB_BEING_DEBUGGED | TIMING_RDTSC | PARENT_PROCESS_CHECK |
                                PTRACE_TRACEME | PROC_MAPS_CHECK;
    constexpr uint32_t ALL     = 0xFFFFFFFF;
}
```

#### Layer 3: Anti-Dump Techniques

```cpp
namespace AntiDumpTechniques {
    // Windows/PE techniques
    constexpr uint32_t ERASE_PE_HEADER          = 1 << 0;
    constexpr uint32_t CORRUPT_PE_HEADER        = 1 << 1;
    constexpr uint32_t RANDOMIZE_PE_FIELDS      = 1 << 2;
    constexpr uint32_t WIPE_DEBUG_DIRECTORY     = 1 << 3;
    constexpr uint32_t WIPE_EXPORT_DIRECTORY    = 1 << 4;
    constexpr uint32_t CORRUPT_IMPORT_DIRECTORY = 1 << 5;
    constexpr uint32_t WIPE_IAT                 = 1 << 6;
    constexpr uint32_t WIPE_TLS_DIRECTORY       = 1 << 7;
    constexpr uint32_t WIPE_EXCEPTION_DIRECTORY = 1 << 8;
    constexpr uint32_t WIPE_RESOURCE_DIRECTORY  = 1 << 9;
    constexpr uint32_t ENCRYPT_SECTION_HEADERS  = 1 << 10;
    constexpr uint32_t MANIPULATE_PEB           = 1 << 11;
    constexpr uint32_t UNLINK_LDR               = 1 << 12;
    constexpr uint32_t SPOOF_MODULE_INFO        = 1 << 13;
    constexpr uint32_t PURGE_WORKING_SET        = 1 << 14;
    constexpr uint32_t VEH_PROTECTION           = 1 << 15;
    constexpr uint32_t CORRUPT_CHECKSUM         = 1 << 16;
    constexpr uint32_t INVALIDATE_DOS_STUB      = 1 << 17;
    constexpr uint32_t SCRAMBLE_OPTIONAL_HEADER = 1 << 18;
    constexpr uint32_t HIDE_SECTION_NAMES       = 1 << 19;
    constexpr uint32_t CORRUPT_RELOCATIONS      = 1 << 20;
    constexpr uint32_t WIPE_RICH_HEADER         = 1 << 21;  // Linux alias: WIPE_BUILD_ID
    constexpr uint32_t CORRUPT_COFF_HEADER      = 1 << 22;  // Linux alias: CORRUPT_DYNAMIC_SECTION
    constexpr uint32_t CORRUPT_DOS_HEADER       = 1 << 23;  // Linux alias: WIPE_ALL_METADATA
    constexpr uint32_t INVALIDATE_NT_SIGNATURE  = 1 << 24;  // Linux alias: SELF_DELETE_EXECUTABLE
    constexpr uint32_t SCRAMBLE_SECTION_ALIGN   = 1 << 25;  // Linux alias: MASK_PROC_MAPS
    constexpr uint32_t MANGLE_ENTRY_POINT       = 1 << 26;

    // Linux/ELF techniques
    constexpr uint32_t DISABLE_CORE_DUMPS       = 1 << 27;
    constexpr uint32_t PRCTL_DUMPABLE           = 1 << 28;
    constexpr uint32_t MADVISE_DONTDUMP         = 1 << 29;
    constexpr uint32_t WIPE_ELF_HEADER          = 1 << 30;
    constexpr uint32_t OBFUSCATE_PHDR           = 1 << 31;

    // Presets
    constexpr uint32_t MINIMAL    = ERASE_PE_HEADER | WIPE_ELF_HEADER | DISABLE_CORE_DUMPS;
    constexpr uint32_t STANDARD   = ERASE_PE_HEADER | CORRUPT_PE_HEADER | WIPE_DEBUG_DIRECTORY |
                                   WIPE_EXPORT_DIRECTORY | MANIPULATE_PEB | DISABLE_CORE_DUMPS |
                                   PRCTL_DUMPABLE | WIPE_ELF_HEADER;
    constexpr uint32_t ALL        = 0xFFFFFFFF;
    constexpr uint32_t AGGRESSIVE = ALL;
}
```

#### Layer 4: Memory Encryption Techniques

```cpp
namespace MemoryEncryptionTechniques {
    constexpr uint32_t CHACHA20_ENCRYPTION = 1 << 0;   // ChaCha20 cipher
    constexpr uint32_t PAGE_GUARD_PROTECTION = 1 << 1; // PAGE_NOACCESS guard
    constexpr uint32_t ON_DEMAND_DECRYPTION  = 1 << 2; // Auto-decrypt on access
    constexpr uint32_t AUTO_RE_ENCRYPTION    = 1 << 3; // Automatic re-encryption
    constexpr uint32_t PER_PAGE_KEYS         = 1 << 4; // Unique key per page
    constexpr uint32_t SECURE_KEY_GENERATION = 1 << 5; // Strong key derivation

    constexpr uint32_t ALL = 0xFFFFFFFF;
}
```

### Builder Pattern API

Use the fluent builder pattern for clean configuration:

```cpp
auto config = Omamori::ProtectionConfig()
    .WithAntiVM(true, AntiVMTechniques::SAFE)               // Layer 1
    .WithAntiDebug(true, AntiDebugTechniques::FAST)         // Layer 2
    .WithAntiDebugThread(true, 200)                          // Background thread
    .WithAntiDump(true, AntiDumpTechniques::STANDARD)       // Layer 3
    .WithMemoryEncryption(false)                             // Layer 4
    .WithCallback(myDetectionHandler);                       // Custom handler

Omamori::Initialize(config);
```

### Preset Configurations

| Preset | Layer 1 | Layer 2 | Layer 3 | Layer 4 | Use Case |
|:-------|:-------:|:-------:|:-------:|:-------:|:---------|
| `Production()` | ❌ | ✅ FAST | ✅ STANDARD | ❌ | General deployment |
| `MaximumProtection()` | ✅ ALL | ✅ ALL | ✅ ALL | ✅ ALL | Maximum security |
| `DebugOnly()` | ❌ | ✅ FAST | ❌ | ❌ | Development testing |
| `Stealth()` | ❌ | ✅ STEALTH | ✅ MINIMAL | ❌ | Low-profile protection |
| `MemoryOnly()` | ❌ | ❌ | ❌ | ✅ ALL | Data protection only |
| `Minimal()` | ❌ | ✅ (no thread) | ❌ | ✅ | Performance-critical |

```cpp
// Quick preset usage
auto config = Omamori::ProtectionConfig::Production();
Omamori::Initialize(config);

// Or with modifications
auto config = Omamori::ProtectionConfig::Production()
    .WithAntiDebugThread(true, 500);  // Slower check interval
Omamori::Initialize(config);
```

### Layer-Only and Single-Technique Helpers

Enable only a specific layer:

```cpp
// Only Layer 2 (Anti-Debug) with all techniques
auto layer2 = Omamori::ProtectionConfig::LayerOnly(2);
Omamori::Initialize(layer2);

// Only Layer 3 (Anti-Dump) with all techniques  
auto layer3 = Omamori::ProtectionConfig::LayerOnly(3);
Omamori::Initialize(layer3);
```

Enable only one specific technique:

```cpp
// Only check PEB.BeingDebugged - fastest possible check
auto single = Omamori::ProtectionConfig::SingleTechnique(
    2,  // Layer 2
    AntiDebugTechniques::PEB_BEING_DEBUGGED
);
Omamori::Initialize(single);

// Only CPUID hypervisor bit check
auto vmSingle = Omamori::ProtectionConfig::SingleTechnique(
    1,  // Layer 1
    AntiVMTechniques::CPUID_CHECK
);
```

### Detection with Specific Techniques

Check for debugger using only certain techniques:

```cpp
// Quick check - PEB only (< 1μs)
bool quick = Omamori::IsDebugged(AntiDebugTechniques::PEB_BEING_DEBUGGED);

// Fast check - PEB + hardware breakpoints (< 5μs)
bool fast = Omamori::IsDebugged(AntiDebugTechniques::FAST);

// Full check - all techniques
bool full = Omamori::IsDebugged(AntiDebugTechniques::ALL);

// Custom combination
uint32_t custom = AntiDebugTechniques::PEB_BEING_DEBUGGED |
                  AntiDebugTechniques::TIMING_RDTSC |
                  AntiDebugTechniques::HARDWARE_BREAKPOINTS;
bool customCheck = Omamori::IsDebugged(custom);
```

Same for VM detection:

```cpp
// Safe check (no timing, no false positives)
bool vmSafe = Omamori::IsInVM(AntiVMTechniques::SAFE);

// Full check with all techniques
bool vmFull = Omamori::IsInVM(AntiVMTechniques::ALL);
```

### Custom Detection Callback

Handle detections without terminating:

```cpp
void MyDetectionHandler(const char* layer, const char* technique) {
    std::cout << "[DETECTION] Layer: " << layer 
              << ", Technique: " << technique << std::endl;
    
    // Log to file, send telemetry, etc.
    LogSecurityEvent(layer, technique);
    
    // Decide action based on technique
    if (strcmp(technique, "TIMING_RDTSC") == 0) {
        // Timing checks can have false positives, just log
        return;
    }
    
    // For definitive detection, take action
    CorruptSensitiveData();
    std::exit(1);
}

int main() {
    auto config = Omamori::ProtectionConfig()
        .WithAntiDebug(true, AntiDebugTechniques::ALL)
        .WithCallback(MyDetectionHandler);  // Callback disables auto-terminate
    
    Omamori::Initialize(config);
}
```

### Helper Methods

Check if a specific technique is enabled in config:

```cpp
auto config = Omamori::ProtectionConfig()
    .WithAntiDebug(true, AntiDebugTechniques::FAST);

// Check individual techniques
bool hasPEB = config.IsAntiDebugTechniqueEnabled(
    AntiDebugTechniques::PEB_BEING_DEBUGGED);  // true

bool hasMemBP = config.IsAntiDebugTechniqueEnabled(
    AntiDebugTechniques::MEMORY_BREAKPOINT);  // false (not in FAST)

// Same for other layers
bool hasMAC = config.IsAntiVMTechniqueEnabled(
    AntiVMTechniques::MAC_ADDRESS);

bool hasVEH = config.IsAntiDumpTechniqueEnabled(
    AntiDumpTechniques::VEH_PROTECTION);
```

### Common Use Cases

**Use Case 1: Desktop Application / Game**

Allow VMs, prevent debugging:

```cpp
auto config = Omamori::ProtectionConfig::Production();
Omamori::Initialize(config);
```

**Use Case 2: License Server**

Fast checks, protect keys in memory:

```cpp
auto config = Omamori::ProtectionConfig()
    .WithAntiDebug(true, AntiDebugTechniques::PEB_BEING_DEBUGGED)
    .WithAntiDebugThread(false)  // No background thread
    .WithMemoryEncryption(true);
Omamori::Initialize(config);

// Store license key encrypted
ENCRYPTED_ARRAY(char, license, 256);
```

**Use Case 3: Banking / Finance Application**

Maximum security, no VMs:

```cpp
auto config = Omamori::ProtectionConfig::MaximumProtection();
Omamori::Initialize(config);
// Will terminate if VM or debugger detected
```

**Use Case 4: Performance-Critical with Logging**

Minimal overhead, log detections:

```cpp
auto config = Omamori::ProtectionConfig()
    .WithAntiDebug(true, AntiDebugTechniques::PEB_BEING_DEBUGGED)
    .WithAntiDebugThread(false)
    .WithCallback([](const char* l, const char* t) {
        syslog(LOG_WARNING, "Security: %s/%s", l, t);
    });
```

**Use Case 5: Stealth Protection**

Low-profile, avoid timing-based detection:

```cpp
auto config = Omamori::ProtectionConfig::Stealth();
Omamori::Initialize(config);
```

### Performance Comparison

| Configuration | Overhead | Techniques |
|:--------------|:---------|:-----------|
| `SingleTechnique(2, PEB_BEING_DEBUGGED)` | ~0.1 μs | 1 |
| `FAST` preset | ~5 μs | 3 |
| `STEALTH` preset | ~10 μs | 3 |
| `ALL` techniques | ~100 μs | 15+ |
| Background thread (100ms) | ~0.001% CPU | Continuous |

**Recommendations:**

- **Hot paths**: Use `SingleTechnique()` or `FAST` preset
- **Production**: Use `Production()` preset
- **Maximum security**: Use `MaximumProtection()` (accepts overhead)

---

## Examples

The `examples/` directory contains comprehensive examples demonstrating all protection features.

### Granular Configuration Examples

These examples show how to use the **bitmask-based technique selection system** to customize protection:

| File | Platform | Description |
|:-----|:---------|:------------|
| [granular_config_windows.cpp](examples/granular_config_windows.cpp) | Windows | Technique-level bitmask selection for all layers |
| [granular_config_linux.cpp](examples/granular_config_linux.cpp) | Linux | Technique-level bitmask selection for all layers |
| [selective_protection.cpp](examples/selective_protection.cpp) | Cross-platform | Layer-level enable/disable examples |
| [simple_selective.cpp](examples/simple_selective.cpp) | Cross-platform | Minimal Layer 2+4 example |

**Key concepts demonstrated:**

1. **Direct bitmask assignment**
   ```cpp
   config.antidebug_techniques = 
       PROC_STATUS_TRACERPID | PTRACE_TRACEME | LD_PRELOAD_CHECK;
   ```

2. **Builder pattern (With* methods)**
   ```cpp
   auto config = ProtectionConfig()
       .WithAntiDebug(true, AntiDebugTechniques::FAST)
       .WithAntiDump(true, AntiDumpTechniques::MINIMAL);
   ```

3. **Preset + customization**
   ```cpp
   auto config = ProtectionConfig::Stealth();
   config.antidebug_techniques &= ~TIMING_RDTSC;  // Remove timing check
   config.antidebug_techniques |= FRIDA_DETECTION; // Add Frida check
   ```

4. **Single technique mode**
   ```cpp
   auto config = ProtectionConfig::SingleTechnique(2, 
       AntiDebugTechniques::PTRACE_TRACEME);
   ```

#### Building the Examples

**Windows (MinGW):**
```bash
cd build
g++ -std=c++17 -DOMAMORI_PLATFORM_WINDOWS -I../include -I../common/include \
    -I../windows/include ../examples/granular_config_windows.cpp \
    ../windows/src/*.cpp -o granular_windows.exe \
    -lntdll -lkernel32 -liphlpapi
```

**Linux:**
```bash
cd build
g++ -std=c++17 -DOMAMORI_PLATFORM_LINUX -I../include -I../common/include \
    -I../linux/include ../examples/granular_config_linux.cpp \
    ../linux/src/*.cpp -o granular_linux -lpthread
```

### Other Examples

Other examples include: [windows_example.cpp](examples/windows_example.cpp), [linux_example.cpp](examples/linux_example.cpp), [test_memory_encryption.cpp](examples/test_memory_encryption.cpp), [example_license_protection.cpp](examples/example_license_protection.cpp), [verify_antidump.cpp](examples/verify_antidump.cpp), [anti_attach_test.cpp](examples/anti_attach_test.cpp).

---

## Excluded Techniques

The following techniques were considered but are **intentionally not implemented** due to complexity, instability, or requiring kernel-level access:

### Windows

| Technique | Reason |
|:---|:---|
| `CreateFakeSections` | Requires modifying PE section count at runtime - can easily corrupt the executable |
| `ScrambleNonExecutedCode` | Needs runtime code analysis to identify cold paths - too complex for reliable implementation |
| `InstallInlineChecks` | Requires binary instrumentation at runtime - would need code injection framework |
| `InsertFakeSections` | Same as CreateFakeSections - dangerous PE manipulation |

### Linux

| Technique | Reason |
|:---|:---|
| `HideFromProcMaps` | Requires kernel module - `/proc/self/maps` is kernel-managed |
| `CorruptProcMem` | Cannot modify `/proc/self/mem` - kernel-managed |
| `ProtectProcAccess` | Requires kernel module to intercept proc filesystem access |
| `MemfdExecution` | Requires `memfd_create()` + `fexecve()` - use case specific, not a protection technique |
| `InsertFakeSections` | Would corrupt ELF structure - section headers aren't needed at runtime anyway |
| `MangleSymbols` | `.dynsym` is needed for dynamic linking - corrupting it crashes the process |
| `ObfuscateMemory` | Would require runtime polymorphic code generation - out of scope |

**Alternative approaches:**
- Instead of `InsertFakeSections`, use `HideSectionNames()` + `ScrambleOptionalHeader()`
- Instead of `MangleSymbols`, use `WipeBuildId()` + `CorruptDynamicSection()`
- Instead of `HideFromProcMaps`, use `MaskProcMaps()` for decoy memory regions

---

## API Reference

### Core API

#### Initialization

```cpp
bool Omamori::Initialize()
bool Omamori::Initialize(const ProtectionConfig& config)
```

Initialize the protection system with the default Production preset or a custom configuration.

**Returns:** `true` if initialization successful

**Example:**

```cpp
// Default (Production preset)
Omamori::Initialize();

// Custom configuration
auto config = Omamori::ProtectionConfig::MaximumProtection();
Omamori::Initialize(config);
```

#### Detection

```cpp
bool Omamori::IsDebugged()
bool Omamori::IsDebugged(uint32_t techniques)
```

Comprehensive debugger detection. The parameterized version allows selecting specific techniques via bitmask.

**Returns:** `true` if debugger detected

**Example:**

```cpp
// Full check with all techniques
if (Omamori::IsDebugged()) {
    HandleDebuggerDetected();
}

// Fast check - only PEB-based techniques
if (Omamori::IsDebugged(AntiDebugTechniques::FAST)) {
    HandleDebuggerDetected();
}

// Single technique - minimal overhead
if (Omamori::IsDebugged(AntiDebugTechniques::PEB_BEING_DEBUGGED)) {
    HandleDebuggerDetected();
}

// Custom combination
uint32_t checks = AntiDebugTechniques::PEB_BEING_DEBUGGED |
                  AntiDebugTechniques::HARDWARE_BREAKPOINTS;
if (Omamori::IsDebugged(checks)) {
    HandleDebuggerDetected();
}
```

```cpp
bool Omamori::IsInVM()
bool Omamori::IsInVM(uint32_t techniques)
```

VM/Hypervisor detection. The parameterized version allows selecting specific techniques.

**Returns:** `true` if running in a virtual machine

**Example:**

```cpp
// Full check
if (Omamori::IsInVM()) {
    std::cout << "Running in VM" << std::endl;
}

// Safe check (no timing-based, fewer false positives)
if (Omamori::IsInVM(AntiVMTechniques::SAFE)) {
    std::cout << "VM detected (safe check)" << std::endl;
}
```

```cpp
void Omamori::TerminateIfDebugged()
```

Check for debugger and immediately terminate if detected.

**Platform Support:** Windows, Linux

#### Version Information

```cpp
const char* Omamori::GetVersion()
```

Get library version string.

**Returns:** Version string (e.g., "1.0.0")

### Secure String Encryption

Compile-time string encryption to protect sensitive strings from static analysis.

```cpp
// ASCII string encryption
auto password = SECURE_STR("MySecretPassword123!");
const char* ptr = password.get();

// Wide string encryption (Windows)
auto wideStr = SECURE_WSTR(L"Unicode Secret!");
const wchar_t* wptr = wideStr.get();

// Alternative macro (shorter)
auto key = XSTR("API_KEY_12345");
std::string decrypted = key.decrypt();

// RAII secure string with automatic wipe
Omamori::SecureString secure("SensitiveData");
// Automatically wiped from memory on destruction
```

Features:

- XOR encryption with line-based key
- Compile-time obfuscation
- Automatic memory wiping on destruction

### Anti-Debug API (Core)

```cpp
// Automatic timing verification
void SensitiveOperation() {
    // Terminate if operation takes > 100ms
    Omamori::AntiDebug::TimingGuard guard(100.0);
  
    ProcessSecretData();
  
} // Automatically checks timing on scope exit
```

#### Protection Thread

Background monitoring thread for continuous protection.

```cpp
namespace Omamori::AntiDebug::ProtectionThread {
    // Start monitoring (interval in milliseconds)
    void Start(unsigned int intervalMs = 500);
  
    // Stop monitoring
    void Stop();
  
    // Set custom callback on detection
    void SetCallback(std::function<void()> callback);
}
```

Example:

```cpp
// Start background monitoring every 500ms
Omamori::AntiDebug::ProtectionThread::Start(500);

// Optional: custom callback
Omamori::AntiDebug::ProtectionThread::SetCallback([]() {
    std::cerr << "Debugger detected by monitoring thread!" << std::endl;
    std::exit(1);
});

// Your application runs here

// Stop monitoring
Omamori::AntiDebug::ProtectionThread::Stop();
```

### Anti-Dump / Anti-VM API (Reference)

Full API surface is available in headers under [windows/include](windows/include) and [linux/include](linux/include). For most use cases, prefer the high-level API (`Initialize`, `IsDebugged`, `IsInVM`) and technique bitmasks.

### Memory Encryption Layer

Transparent memory encryption protects sensitive data at runtime. Data is stored encrypted in memory and automatically decrypted only when accessed.

#### EncryptionManager API

```cpp
namespace Omamori::MemoryEncryption {
    class EncryptionManager {
    public:
        // Initialization
        bool Initialize();
        void Shutdown();
      
        // Memory allocation
        void* AllocateEncrypted(size_t size);
        void FreeEncrypted(void* ptr);
      
        // Encryption control
        bool EncryptRegion(void* address, size_t size);
        bool DecryptRegion(void* address, size_t size);
        bool ProtectAndEncrypt(void* address, size_t size);
        bool UnprotectAndDecrypt(void* address, size_t size);
      
        // Configuration
        void SetAutoReEncrypt(bool enable);       // Default: true
        void SetDecryptTimeout(uint32_t ms);      // Default: 100ms
      
        // Statistics
        Stats GetStats() const;
    };
}
```

#### Basic Usage

```cpp
using namespace Omamori::MemoryEncryption;

// Initialize encryption manager
EncryptionManager::GetInstance().Initialize();

// Allocate 4KB encrypted memory
void* encrypted_mem = EncryptionManager::GetInstance().AllocateEncrypted(4096);

// Use normally - automatic decryption on access!
char* data = static_cast<char*>(encrypted_mem);
strcpy(data, "Secret data");  // Automatically decrypted here
printf("%s\n", data);          // Automatically decrypted here

// Re-encrypt when not in use
EncryptionManager::GetInstance().ProtectAndEncrypt(encrypted_mem, 4096);

// Cleanup
EncryptionManager::GetInstance().FreeEncrypted(encrypted_mem);
```

#### Template-Based Usage (RAII)

```cpp
// Encrypted buffer with automatic management
EncryptedBuffer<int> numbers(100);

for (int i = 0; i < 100; i++) {
    numbers[i] = i * i;  // Transparent access
}

// Automatic cleanup on scope exit
```

#### Helper Macros

```cpp
// Single encrypted variable
ENCRYPTED_VAR(int, api_key, 0x12345678);
int key = api_key_encrypted[0];  // Transparent

// Encrypted array
ENCRYPTED_ARRAY(char, password, 256);
strcpy(password.data(), "MyPassword");  // Transparent
```

#### Use Cases

**API Keys / Credentials:**

```cpp
EncryptedBuffer<char> api_key(128);
strcpy(api_key.data(), "sk-1234567890abcdef");
// Memory dump shows CIPHERTEXT, not plaintext
make_api_call(api_key.data());  // Auto-decrypt
```

**License Keys:**

```cpp
struct License {
    char key[128];
    uint64_t expiry;
};

EncryptedBuffer<License> license(1);
license[0].key = load_license();
// Protected in memory between validations
```

**Session Tokens:**

```cpp
EncryptedBuffer<uint8_t> session_token(64);
generate_secure_token(session_token.data());
// Only plaintext during active use
```

### Direct & Indirect Syscalls (Windows Only)

Bypass usermode hooks and EDR monitoring by executing syscalls directly or indirectly.

```cpp
namespace Omamori::Windows::Syscall {
    // Common syscall wrappers
    namespace Common {
        NTSTATUS NtQueryInformationProcess(...);
        NTSTATUS NtSetInformationThread(...);
        NTSTATUS NtQuerySystemInformation(...);
        NTSTATUS NtClose(...);
        NTSTATUS NtWriteVirtualMemory(...);  // NEW
        NTSTATUS NtReadVirtualMemory(...);   // NEW
    }
  
    // Syscall stub management (Direct & Indirect)
    namespace StubManager {
        SyscallStub* GetStub(const char* functionName);
        SyscallStub* CreateIndirectStub(const char* functionName);  // NEW
        void ClearCache();
    }
  
    // Hook detection
    namespace Detector {
        bool IsFunctionHooked(const char* functionName);
    }
    
    // Halo's Gate - SSN resolution when hooked (NEW)
    namespace HalosGate {
        bool IsHooked(void* functionAddress);
        DWORD ExtractSSN(void* functionAddress);
        DWORD ResolveFromNeighbor(void* functionAddress, int direction);
        DWORD ResolveSyscallNumber(const char* functionName);  // Auto-resolve
        void* FindCleanSyscallAddress();  // Find unhooked syscall;ret
    }
    
    // Indirect Syscalls - EDR evasion (NEW)
    namespace IndirectSyscall {
        void* GetSyscallAddress(const char* functionName);
        NTSTATUS Execute(DWORD ssn, void* syscallAddr, ...);
    }
}
```

Example:

```cpp
#ifdef _WIN32
// Direct syscall bypassing any hooks
DWORD debugPort = 0;
NTSTATUS status = Omamori::Syscall::Common::NtQueryInformationProcess(
    GetCurrentProcess(),
    static_cast<PROCESSINFOCLASS>(7),  // ProcessDebugPort
    &debugPort,
    sizeof(debugPort),
    nullptr
);

if (NT_SUCCESS(status) && debugPort != 0) {
    // Debugger detected
}
#endif
```

---

## Build Instructions

### Prerequisites

**Linux:**

```bash
sudo apt-get install build-essential cmake g++
```

**Windows:**

- Visual Studio 2019/2022 with C++ tools
- OR MinGW-w64 (GCC 9.0+)
- CMake 3.15+

### Build Options

```bash
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \      # Release or Debug
    -DBUILD_EXAMPLES=ON \              # Build example programs (default: ON)
    -DBUILD_TESTS=ON \                 # Build test suite (default: ON)
    -DBUILD_SHARED_LIBS=OFF            # Build type (default: OFF = static)
```

### Build Type Comparison

| Option         | Binary Size | Optimization | Debug Info |
| -------------- | ----------- | ------------ | ---------- |
| Release        | Smallest    | -O3/-O2      | Stripped   |
| Debug          | Largest     | -O0          | Full       |
| RelWithDebInfo | Medium      | -O2          | Partial    |
| MinSizeRel     | Smallest    | -Os          | Stripped   |

### Linux Build

**Standard Build:**

```bash
cd omamori
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

**Output Files:**

- Library: `build/libOmamori.a` (~230 KB)
- Example: `build/omamori_example_linux` (~160 KB)
- Tests: `build/omamori_test_linux`

**Run Tests:**

```bash
./omamori_test_linux
```

**Run Example:**

```bash
./omamori_example_linux
```

### Windows Build

**Visual Studio:**

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

**MinGW:**

```bash
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
mingw32-make
```

**Output Files:**

- Library: `build/Release/Omamori.lib`
- Example: `build/Release/omamori_example_windows.exe`
- Tests: `build/Release/omamori_test_windows.exe`

### Installation

**System-wide Installation (Linux):**

```bash
cd build
sudo make install
```

Installs to:

- Library: `/usr/local/lib/libOmamori.a`
- Headers: `/usr/local/include/omamori/`
- CMake config: `/usr/local/lib/cmake/Omamori/`

### Using in Your Project

```cmake
find_package(Omamori REQUIRED)
target_link_libraries(your_target PRIVATE Omamori::Omamori)
```

### Compiler Flags

**Linux (GCC/Clang):**

```bash
-std=c++17
-Wall -Wextra -Wpedantic
-fno-rtti -fno-exceptions
-O3 (Release)
-fstack-protector-strong
-D_FORTIFY_SOURCE=2
```

**Windows (MSVC):**

```bash
/std:c++17
/W4 /WX-
/GR- (no RTTI)
/O2 (Release)
/DYNAMICBASE /NXCOMPAT
```

---

## Testing

### Test Coverage Summary

All four protection layers are covered by comprehensive test suites:

**Layer 1 (Anti-VM):**

- `omamori_antivm_test_linux` - 11 detection techniques
- `omamori_antivm_test_windows` - 12 detection techniques

**Layer 2 (Anti-Debug):**

- `omamori_test_linux` - 40+ Linux techniques
- `omamori_test_windows` - 40+ Windows techniques
- `omamori_anti_attach_test` - ptrace attachment verification

**Layer 3 (Anti-Dump):**

- `omamori_verify_antidump` - Header corruption verification
- Integrated tests in `omamori_test_linux` and `omamori_test_windows`

**Layer 4 (Memory Encryption):**

- `omamori_memory_encryption_test` - 6 comprehensive tests
- `omamori_license_example` - Real-world license protection demo

**Selective Protection:**

- `omamori_selective_protection` - 6 configuration examples
- `examples/simple_selective.cpp` - Minimal Layer 2+4 example

### Running Test Suite

```bash
# Linux
cd build
./omamori_test_linux

# Windows
cd build\Release
omamori_test_windows.exe
```

### Test Results

The test suites validate:

- All anti-debug techniques (PEB, ptrace, timing, etc.)
- All anti-dump protections (PE/ELF, memory, core dumps)
- Anti-VM detection (CPUID, DMI, containers)
- Direct syscalls and hook detection (Windows)
- String encryption and secure memory
- Protection threads and callbacks
- Memory encryption (allocation, encryption, decryption)
- **Granular configuration system** (presets, bitmasks, builder pattern)
- **LayerOnly() and SingleTechnique() factories**
- **IsXxxTechniqueEnabled() helpers**

**Latest Test Results:**

| Platform | Tests | Passed | Failed | Success Rate |
|----------|-------|--------|--------|-------------|
| Windows (MinGW) | 94 | 94 | 0 | **100%** ✅ |
| Linux (GCC) | 77 | 77 | 0 | **100%** ✅ |

Expected output shows PASS/FAIL for each technique with details.

### License Protection Example

```cpp
#include <omamori.hpp>
#include "omamori/memory_encryption.hpp"

struct LicenseKey {
    char key[256];
    uint64_t expiry_timestamp;
    uint32_t user_id;
};

int main() {
    // Initialize with Production preset (no Anti-VM)
    Omamori::Initialize();
  
    // Initialize memory encryption
    Omamori::MemoryEncryption::EncryptionManager::GetInstance().Initialize();
  
    // Store license in encrypted memory
    Omamori::MemoryEncryption::EncryptedBuffer<LicenseKey> license(1);
  
    // Load license (automatic decryption on access)
    strcpy(license[0].key, LoadLicenseFromFile());
    license[0].expiry_timestamp = GetExpiryTimestamp();
    license[0].user_id = GetUserId();
  
    // Verify license
    if (!VerifyLicenseSignature(license[0].key)) {
        std::cerr << "Invalid license" << std::endl;
        return 1;
    }
  
    // Check expiry
    if (license[0].expiry_timestamp < time(nullptr)) {
        std::cerr << "License expired" << std::endl;
        return 1;
    }
  
    // Application logic with protected license
    RunApplication();
  
    // License automatically encrypted when not accessed
    return 0;
}
```

---

## Performance

### Overhead Analysis

**Normal Operation:**

- CPU: < 0.5%
- Memory: < 1 MB
- Binary size increase: ~200-300 KB (static link)

**Protection Thread:**

- CPU: ~0.1% (500ms interval)
- Context switches: ~10-20/sec

**String Encryption:**

- Compile-time: no runtime overhead
- Decryption: < 1μs per string

**Memory Encryption:**

- Allocation: ~50μs
- First access (page fault): ~10μs
- Subsequent access: 0μs (after decrypt)
- Re-encryption: ~5μs

### Optimization Tips

1. **Adjust Check Intervals:** Increase protection thread interval for lower overhead
2. **Selective Protection:** Enable only needed techniques for your use case
3. **Release Builds:** Always use Release builds for production (optimizations enabled)
4. **Static Linking:** Prefer static linking for better performance

---

## Security Considerations

### Important Limitations

1. **Not Absolute Protection:** No software-only protection can defend against determined attackers with kernel-level access and physical hardware control.
2. **Defense in Depth:** Omamori provides multiple protection layers. Use all modules together for best results.
3. **False Positives:**

   - Timing-based detection may trigger on slow systems
   - VM detection will trigger in legitimate virtualized environments
   - Some anti-debug techniques trigger during normal development debugging
4. **Aggressive Techniques:**

   - Header erasure prevents normal debugging tools from working
   - Protection thread adds minimal overhead but runs continuously
   - Some techniques may trigger anti-virus heuristics
5. **Platform Compatibility:**

   - Windows: Requires Windows 10+ for full functionality
   - Linux: Requires kernel 3.10+ for full functionality
   - Some techniques require elevated privileges

### Best Practices

1. **Testing:** Thoroughly test in your target environments before deployment
2. **Logging:** Implement logging to understand false positive rates
3. **Graceful Degradation:** Consider warning users instead of immediately terminating
4. **Update Regularly:** Protection techniques evolve; keep library updated
5. **Legal Compliance:** Ensure usage complies with applicable laws and ToS

### Known Limitations

**Windows:**

- Kernel debuggers can bypass all usermode protections
- Requires administrator privileges for some techniques
- May conflict with anti-virus software in rare cases

**Linux:**

- ptrace techniques may conflict with development tools
- Root/CAP_SYS_PTRACE can bypass ptrace protections
- Container detection may not work in all container runtimes

---

## Technical Details

### Implementation Statistics

- **Total Files:** 25+
- **Lines of Code:** ~5,500 LOC
- **Header Files:** 13 (.hpp)
- **Implementation:** 10 (.cpp)
- **Examples:** 10
- **Tests:** 2 comprehensive suites

**Code Distribution:**

- Windows modules: ~2,500 LOC
- Linux modules: ~2,300 LOC
- Common modules: ~200 LOC
- Tests: ~800 LOC

**Binary Sizes (Release, stripped):**

- Linux static library: ~230 KB
- Linux example: ~160 KB
- Windows static library: ~250 KB

### Architecture Patterns

- **RAII:** `TimingGuard`, `SecureString`, `EncryptedBuffer` - automatic cleanup
- **Singleton:** `EncryptionManager`, internal API accessors
- **Factory:** Syscall stub generation
- **Observer:** Protection thread callbacks
- **Strategy:** Multiple detection method implementations

### Supported Compilers

**Windows:**

- MSVC 2019+
- MinGW-w64 (GCC 9.0+)
- Clang 10.0+

**Linux:**

- GCC 7.0+
- Clang 6.0+

### Supported Architectures

- x86 (32-bit)
- x64 (64-bit)
- ARM64 (partial support, testing required)

---

**Omamori** - Protection through depth and diversity.
