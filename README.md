# Omamori - Modern Software Protection Library

A cross-platform protection library implementing advanced anti-debugging, anti-dumping, anti-virtualization, and memory encryption techniques for Windows and Linux.

**Platform Support:** Windows | Linux | **Architecture:** x86 | x64 | **License:** MIT | **C++ Standard:** 17

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Selective Protection](#selective-protection)
- [API Reference](#api-reference)
- [Build Instructions](#build-instructions)
- [Testing](#testing)
- [Integration Examples](#integration-examples)
- [Performance](#performance)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Overview

Omamori is a production-ready software protection library designed to defend applications against reverse engineering, debugging, memory dumping, and virtualized analysis environments. It implements over 60 modern protection techniques across Windows and Linux platforms.

### Protection Stack

┌───────────────────────────────────────────────────────────────┐
│                    OMAMORI PROTECTION STACK                   │
├───────────────────────────────────────────────────────────────┤
│  Layer 4: Memory Encryption                                   │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  Transparent memory encryption with on-demand decrypt    │ │
│  │  • Stream cipher (XOR/ChaCha20)                          │ │
│  │  • Page-level protection (PROT_NONE/PAGE_NOACCESS)       │ │
│  │  • Automatic SIGSEGV/VEH handler                         │ │
│  └──────────────────────────────────────────────────────────┘ │
├───────────────────────────────────────────────────────────────┤
│  Layer 3: Anti-Dump                                           │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  Runtime memory corruption & dump prevention             │ │
│  │  • PE/ELF header erasure                                 │ │
│  │  • Core dump disabling (setrlimit + prctl)               │ │
│  │  • Continuous re-corruption thread                       │ │
│  │  • PEB/LDR unlinking (Windows)                           │ │
│  └──────────────────────────────────────────────────────────┘ │
├───────────────────────────────────────────────────────────────┤
│  Layer 2: Anti-Debug                                          │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  Multi-vector debugger detection & prevention            │ │
│  │  • PEB/TEB inspection (50+ checks)                       │ │
│  │  • Hardware breakpoint detection                         │ │
│  │  • Timing attacks (RDTSC, sleep)                         │ │
│  │  • ptrace self-attach (Linux)                            │ │
│  │  • Framework detection (GDB, LLDB, OllyDbg, x64dbg)      │ │
│  └──────────────────────────────────────────────────────────┘ │
├───────────────────────────────────────────────────────────────┤
│  Layer 1: Anti-Virtualization                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  VM & container detection                                │ │
│  │  • CPUID hypervisor bit                                  │ │
│  │  • DMI/SMBIOS fingerprinting                             │ │
│  │  • Container detection (cgroup, /.dockerenv)             │ │
│  │  • VM artifacts (VMware tools, VBox drivers)             │ │
│  └──────────────────────────────────────────────────────────┘ │
├───────────────────────────────────────────────────────────────┤
│  Base: System Integration                                     │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  • Direct syscalls (Windows)                             │ │
│  │  • Secure string encryption (compile-time XOR)           │ │
│  │  • Cross-platform abstraction layer                      │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘

---

## Features

### Cross-Platform Protection

- Unified API for Windows and Linux
- Platform-specific optimizations
- Compile-time string encryption
- Runtime memory protection
- Direct syscalls (Windows)

### Layer 1: Anti-Virtualization

**Linux (11 techniques):**

- CPUID hypervisor bit detection
- DMI/SMBIOS string analysis
- MAC address fingerprinting (VMware, VirtualBox, Hyper-V, Parallels)
- VM device detection (/dev/vmware, /dev/vboxguest, etc.)
- VMware-specific artifacts
- VirtualBox-specific signatures
- KVM detection
- QEMU detection
- Docker container detection (/.dockerenv)
- cgroup-based container detection
- systemd-detect-virt integration

**Windows (12 techniques):**

- CPUID hypervisor bit detection
- Registry checks (HARDWARE\\DEVICEMAP\\Scsi, BIOS info)
- MAC address detection (00:05:69, 00:0C:29, 08:00:27, etc.)
- Device driver detection (VBoxGuest, VMware tools)
- SMBIOS/firmware checks
- Process detection (vmtoolsd, vboxservice)
- Service detection (VMware services, VBox services)
- File system artifacts (C:\\Program Files\\VMware)
- WMI queries (Win32_ComputerSystem, BIOS manufacturer)
- Timing anomalies (RDTSC in VM)
- I/O port checks (VMware backdoor port)
- Hyper-V specific detection

### Layer 2: Anti-Debug

**50+ detection techniques including:**

- PEB/TEB inspection (BeingDebugged, NtGlobalFlag, heap flags)
- Hardware breakpoint detection (DR0-DR7 registers)
- Timing attacks (RDTSC, QueryPerformanceCounter)
- ptrace manipulation (Linux: TRACEME, self-attach)
- /proc filesystem checks (TracerPid, maps, status)
- API-based detection (CheckRemoteDebuggerPresent, NtQueryInformationProcess)
- Exception-based detection (CloseHandle, OutputDebugString)
- Framework detection (Frida, GDB, LLDB, x64dbg, OllyDbg)
- Environment analysis (LD_PRELOAD, debug variables)
- Parent process verification
- Background monitoring thread with customizable intervals

### Layer 3: Anti-Dump

**PE/ELF header manipulation:**

- Magic bytes corruption
- DOS header erasure
- PE/ELF header complete erasure
- Section header removal
- Memory page protection (PAGE_NOACCESS/PROT_NONE)
- VEH/SIGSEGV exception handling
- PEB/LDR unlinking (Windows)
- Continuous re-corruption thread
- Core dump prevention (setrlimit + prctl on Linux)
- /proc/self/maps obfuscation

### Layer 4: Memory Encryption

**Transparent on-demand encryption:**

- Page-level protection with signal/exception handlers
- Stream cipher (XOR, upgradeable to ChaCha20)
- Automatic decryption on memory access (SIGSEGV/VEH)
- Per-page unique encryption keys
- Automatic re-encryption after timeout
- Zero application code changes
- Template-based RAII interface
- Protects credentials, license keys, sensitive data

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

```bash
# Using Visual Studio
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# Using MinGW
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
mingw32-make
```

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

---

## Selective Protection

### Overview

Omamori provides four independent protection layers that can be enabled or disabled individually. This allows fine-grained control over which protections are active based on your deployment scenario.

### Configuration Structure

```cpp
struct ProtectionConfig {
    // Layer 1: Anti-Virtualization
    bool enable_antivm;              // Enable VM detection
    uint32_t antivm_methods;         // Bitmask of detection methods
  
    // Layer 2: Anti-Debug
    bool enable_antidebug;           // Enable debugger detection
    bool enable_antidebug_thread;    // Background protection thread
    uint32_t antidebug_check_interval_ms;  // Thread check interval
  
    // Layer 3: Anti-Dump
    bool enable_antidump;            // Enable dump prevention
    bool erase_headers;              // Corrupt PE/ELF headers
    bool disable_core_dumps;         // Disable core dumps (Linux)
    bool enable_prctl_protection;    // prctl protection (Linux)
  
    // Layer 4: Memory Encryption
    bool enable_memory_encryption;   // Available for manual use
};
```

### Preset Configurations

**1. Production (Default)**

Recommended for production deployments. Anti-VM is disabled to allow legitimate users running in virtual machines.

```cpp
auto config = Omamori::ProtectionConfig::Production();
Omamori::Initialize(config);
```

Configuration:

- Layer 1 (Anti-VM): OFF
- Layer 2 (Anti-Debug): ON (with background thread)
- Layer 3 (Anti-Dump): ON (full protection)
- Layer 4 (Memory Encryption): OFF (manual activation)

**2. Maximum Protection**

All four layers enabled. Highest security level. Application will terminate if VM is detected.

```cpp
auto config = Omamori::ProtectionConfig::MaximumProtection();
Omamori::Initialize(config);
```

Configuration:

- All layers: ON

**3. Debug-Only**

Only anti-debug protection enabled. Suitable for development and testing environments.

```cpp
auto config = Omamori::ProtectionConfig::DebugOnly();
Omamori::Initialize(config);
```

Configuration:

- Layer 2 (Anti-Debug): ON
- All other layers: OFF

**4. Minimal**

Lightweight protection with anti-debug (no background thread) and memory encryption. Suitable for performance-sensitive applications.

```cpp
auto config = Omamori::ProtectionConfig::Minimal();
Omamori::Initialize(config);
```

Configuration:

- Layer 2 (Anti-Debug): ON (no background thread)
- Layer 4 (Memory Encryption): ON (manual use)
- Layers 1, 3: OFF

**5. Memory-Only**

Only memory encryption layer enabled. For applications focusing solely on protecting sensitive data.

```cpp
auto config = Omamori::ProtectionConfig::MemoryOnly();
Omamori::Initialize(config);
```

Configuration:

- Layer 4 (Memory Encryption): ON
- All other layers: OFF

### Custom Configuration Examples

**Example 1: Layer 2 and 4 Only**

```cpp
#include <omamori.hpp>

int main() {
    Omamori::ProtectionConfig config;
    config.enable_antivm = false;              // Layer 1: OFF
    config.enable_antidebug = true;            // Layer 2: ON
    config.enable_antidebug_thread = false;    // No background thread
    config.enable_antidump = false;            // Layer 3: OFF
    config.enable_memory_encryption = true;    // Layer 4: ON
  
    Omamori::Initialize(config);
  
    // Your application code
    return 0;
}
```

**Example 2: Production without Header Erasure**

```cpp
auto config = Omamori::ProtectionConfig::Production();
config.erase_headers = false;  // Keep headers intact for debugging

Omamori::Initialize(config);
```

**Example 3: Anti-VM with Selective Methods**

```cpp
Omamori::ProtectionConfig config;
config.enable_antivm = true;

// Only use fast detection methods (CPUID + MAC address)
#ifdef __linux__
using namespace Omamori::Linux::AntiVM;
config.antivm_methods = CPUID_CHECK | MAC_ADDRESS;
#else
using namespace Omamori::Windows::AntiVM;
config.antivm_methods = CPUID_CHECK | MAC_ADDRESS;
#endif

config.enable_antidebug = false;
config.enable_antidump = false;

Omamori::Initialize(config);
```

**Example 4: Fine-Grained Control**

```cpp
Omamori::ProtectionConfig config;

// Layer 1: Disabled
config.enable_antivm = false;

// Layer 2: Enabled with custom interval
config.enable_antidebug = true;
config.enable_antidebug_thread = true;
config.antidebug_check_interval_ms = 1000;  // Check every 1 second

// Layer 3: Partial protection
config.enable_antidump = true;
config.disable_core_dumps = true;       // Disable core dumps
config.enable_prctl_protection = true;  // Linux prctl
config.erase_headers = false;           // Keep headers intact

// Layer 4: Disabled
config.enable_memory_encryption = false;

Omamori::Initialize(config);
```

### Common Use Cases

**Use Case 1: Desktop Application / Game**

Requirements: Prevent debugging but allow VMs (users may test in virtual environments).

```cpp
auto config = Omamori::ProtectionConfig::Production();
Omamori::Initialize(config);
```

**Use Case 2: License Server**

Requirements: Protect license keys, prevent debugging, minimal overhead.

```cpp
auto config = Omamori::ProtectionConfig::Minimal();
Omamori::Initialize(config);

// Protect license key in encrypted memory
OMAMORI_ENCRYPTED_BUFFER(license, char, 256);
strcpy(license.get(), "YOUR-LICENSE-KEY");
```

**Use Case 3: Banking / Finance Application**

Requirements: Maximum security, no VMs allowed.

```cpp
auto config = Omamori::ProtectionConfig::MaximumProtection();
Omamori::Initialize(config);
```

Warning: Application will terminate if running in a VM.

**Use Case 4: Development / Testing**

Requirements: Only prevent debugging during testing.

```cpp
auto config = Omamori::ProtectionConfig::DebugOnly();
Omamori::Initialize(config);
```

### Performance Considerations

| Layer                       | Performance Impact | Notes                                      |
| --------------------------- | ------------------ | ------------------------------------------ |
| Layer 1 (Anti-VM)           | ~50μs one-time    | Minimal impact, executed once at startup   |
| Layer 2 (Anti-Debug)        | ~1μs per check    | Continuous overhead with background thread |
| Layer 3 (Anti-Dump)         | ~100μs one-time   | Only executed at startup                   |
| Layer 4 (Memory Encryption) | ~10μs per access  | Only affects encrypted memory regions      |

**Recommendations:**

- **Production deployments**: Use Production preset (Layer 2 + 3)
- **High security**: Use MaximumProtection (all 4 layers)
- **Performance-critical**: Use Minimal (Layer 2 without thread)

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
```

Comprehensive debugger detection using all available techniques.

**Returns:** `true` if debugger detected

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

### Anti-Debug API

#### Windows Anti-Debug

```cpp
namespace Omamori::Windows::AntiDebug::Detector {
    // PEB-based detection
    bool CheckPEBBeingDebugged();       // BeingDebugged flag
    bool CheckPEBNtGlobalFlag();        // NtGlobalFlag analysis
    bool CheckPEBHeapFlags();           // Heap flags inspection
  
    // Hardware breakpoint detection
    bool CheckHardwareBreakpoints();    // DR0-DR7 registers
    void ClearHardwareBreakpoints();    // Clear all hardware BP
  
    // Timing-based detection
    bool CheckTimingRDTSC();            // RDTSC instruction timing
    bool CheckTimingQueryPerformanceCounter();  // QPC timing
  
    // API-based detection
    bool CheckRemoteDebugger();         // CheckRemoteDebuggerPresent
    bool CheckDebugPort();              // NtQueryInformationProcess
    bool CheckDebugFlags();             // ProcessDebugFlags
    bool CheckDebugObject();            // ProcessDebugObjectHandle
  
    // Exception-based detection
    bool CheckCloseHandleException();   // Invalid handle exception
    bool CheckOutputDebugString();      // OutputDebugString behavior
  
    // System checks
    bool CheckKernelDebugger();         // Kernel debugger presence
    bool CheckParentProcess();          // Parent process analysis
  
    // Thread protection
    void HideThreadFromDebugger();      // Hide current thread
  
    // Comprehensive check
    bool IsDebugged();                  // All techniques combined
}
```

#### Linux Anti-Debug

```cpp
namespace Omamori::Linux::AntiDebug::Detector {
    // ptrace-based detection
    bool CheckPtraceTraceme();          // PTRACE_TRACEME test
    bool CheckPtraceAttach();           // Fork + attach test
    bool BlockPtrace();                 // Block external ptrace
    bool BlockPtraceAdvanced();         // Self-attach protection
  
    // /proc filesystem checks
    bool CheckProcStatusTracerPid();    // TracerPid monitoring
    bool CheckProcMaps();               // Memory maps analysis
  
    // Environment checks
    bool CheckLdPreload();              // LD_PRELOAD detection
    bool CheckDebugEnvironment();       // Debug env variables
  
    // Timing analysis
    bool CheckTiming();                 // Clock timing anomalies
  
    // Process analysis
    bool CheckParentProcess();          // Parent process name
    bool CheckParentCmdline();          // Parent command line
  
    // Framework detection
    bool CheckFrida();                  // Frida artifacts
    bool CheckGDB();                    // GDB presence
    bool CheckLLDB();                   // LLDB presence
  
    // Comprehensive check
    bool IsDebugged();                  // All techniques combined
}
```

#### Timing Guard (RAII)

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

### Anti-Dump API

#### Windows Anti-Dump

```cpp
namespace Omamori::Windows::AntiDump::Protection {
    // PE header manipulation
    void CorruptPEHeader();             // Corrupt PE header
    void EraseDOSHeader();              // Erase DOS header
    void ErasePEHeader();               // Erase PE header completely
  
    // Memory protection
    void ProtectHeaderMemory();         // Set PAGE_NOACCESS
    void InstallVEHProtection();        // VEH exception handler
  
    // PEB manipulation
    void UnlinkFromPEB();               // Unlink from module list
  
    // Continuous protection
    void StartContinuousProtection(unsigned int intervalMs);
    void StopContinuousProtection();
}
```

#### Linux Anti-Dump

```cpp
namespace Omamori::Linux::AntiDump::Protection {
    // ELF manipulation
    void CorruptELFHeader();            // Corrupt ELF header
    void EraseSectionHeaders();         // Erase section headers
  
    // Memory protection
    void ProtectMemory();               // mprotect headers
  
    // Core dump prevention
    void DisableCoreDumps();            // setrlimit + prctl
    void SetPrctlProtections();         // Additional prctl flags
  
    // Obfuscation
    void ObfuscateProcMaps();           // Hide from /proc/self/maps
  
    // Comprehensive protection
    void AntiDumpTechniques();          // Apply all techniques
}
```

### Anti-VM API

#### Linux Anti-VM

```cpp
namespace Omamori::Linux::AntiVM::Detector {
    // Detection methods
    bool CheckCPUID();                  // Hypervisor CPUID bit
    bool CheckDMI();                    // DMI/SMBIOS strings
    bool CheckMACAddress();             // VM MAC prefixes
  
    // Specific VM detection
    bool CheckVMware();                 // VMware artifacts
    bool CheckVirtualBox();             // VirtualBox artifacts
    bool CheckKVM();                    // KVM detection
    bool CheckQEMU();                   // QEMU detection
  
    // Container detection
    bool CheckDocker();                 // Docker environment
    bool IsContainerized();             // Generic container check
  
    // System tools
    bool CheckSystemdDetectVirt();      // systemd-detect-virt
  
    // Comprehensive checks
    bool IsVirtualMachine();            // All VM checks
    const char* GetVMType();            // Get detected VM type
  
    // Actions
    void TerminateIfVM();               // Exit if VM detected
}
```

#### Windows Anti-VM

```cpp
namespace Omamori::Windows::AntiVM::Detector {
    // Detection methods
    bool CheckCPUID();                  // Hypervisor CPUID bit
    bool CheckRegistry();               // Registry artifacts
    bool CheckMACAddress();             // VM MAC prefixes
  
    // Specific VM detection
    bool CheckVMware();                 // VMware artifacts
    bool CheckVirtualBox();             // VirtualBox artifacts
    bool CheckHyperV();                 // Hyper-V detection
    bool CheckQEMU();                   // QEMU detection
  
    // System checks
    bool CheckProcesses();              // VM processes
    bool CheckServices();               // VM services
    bool CheckFiles();                  // VM files
    bool CheckDevices();                // VM devices
  
    // Firmware checks
    bool CheckSMBIOS();                 // SMBIOS strings
    bool CheckWMI();                    // WMI queries
  
    // Comprehensive checks
    bool IsVirtualMachine();            // All VM checks
    const char* GetVMType();            // Get detected VM type
  
    // Actions
    void TerminateIfVM();               // Exit if VM detected
}
```

Example:

```cpp
#ifdef __linux__
if (Omamori::Linux::AntiVM::Detector::IsVirtualMachine()) {
    const char* vmType = Omamori::Linux::AntiVM::Detector::GetVMType();
    std::cout << "Detected VM: " << vmType << std::endl;
  
    // Optionally terminate
    Omamori::Linux::AntiVM::Detector::TerminateIfVM();
}
#endif
```

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
        EncryptionStats GetStats();
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

### Direct Syscalls (Windows Only)

Bypass usermode hooks by executing syscalls directly.

```cpp
namespace Omamori::Windows::Syscall {
    // Common syscall wrappers
    namespace Common {
        NTSTATUS NtQueryInformationProcess(...);
        NTSTATUS NtSetInformationThread(...);
        NTSTATUS NtQuerySystemInformation(...);
        NTSTATUS NtClose(...);
    }
  
    // Syscall stub management
    namespace StubManager {
        SyscallStub* GetStub(const char* functionName);
        void ClearCache();
    }
  
    // Hook detection
    namespace Detector {
        bool IsFunctionHooked(const char* functionName);
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
- Selective layer activation

Expected output shows PASS/FAIL for each technique with details.

### Manual Testing

**Linux - Anti-Debug:**

```bash
# Should detect and terminate
gdb ./omamori_example_linux

# Should detect ptrace
strace ./omamori_example_linux
```

**Linux - Anti-Dump:**

```bash
# Core dump should be prevented
./omamori_example_linux &
gcore $(pidof omamori_example_linux)
```

**Linux - Anti-VM:**

```bash
# Run in VM - should detect virtualization
./omamori_antivm_test_linux
```

**Windows - Anti-Debug:**

```bash
# Should detect and terminate
x64dbg omamori_example_windows.exe
windbg omamori_example_windows.exe
```

**Windows - Anti-VM:**

```bash
# Run in VM - should detect virtualization
omamori_antivm_test_windows.exe
```

---

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

## License

MIT License

Copyright (c) 2026 Omamori Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

**Omamori** - Protection through depth and diversity.
